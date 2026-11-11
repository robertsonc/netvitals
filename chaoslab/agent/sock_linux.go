//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

const kernelRxStamps = true

// enableRxMeta turns on kernel receive timestamps and TTL/TOS reporting for a UDP socket.
func enableRxMeta(c syscall.RawConn) (kernelTS bool) {
	_ = c.Control(func(fd uintptr) {
		kernelTS = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1) == nil
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVTTL, 1)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVTOS, 1)
	})
	return kernelTS
}

// parseRxMeta extracts the kernel receive timestamp (0 if absent), TTL and TOS from ancillary data.
func parseRxMeta(oob []byte) (ts int64, ttl, tos uint8) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, 0, 0
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == syscall.SO_TIMESTAMPNS &&
			len(m.Data) >= int(unsafe.Sizeof(syscall.Timespec{})):
			t := (*syscall.Timespec)(unsafe.Pointer(&m.Data[0]))
			ts = int64(t.Sec)*1e9 + int64(t.Nsec)
		case m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_TTL && len(m.Data) >= 4:
			ttl = uint8(*(*int32)(unsafe.Pointer(&m.Data[0])))
		case m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_TOS && len(m.Data) >= 1:
			tos = m.Data[0]
		}
	}
	return ts, ttl, tos
}

// setTOS marks every packet sent on the socket. Returns false when the OS refused.
func setTOS(c syscall.RawConn, tos int) bool {
	ok := false
	_ = c.Control(func(fd uintptr) {
		ok = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos) == nil
	})
	return ok
}

// tosControl builds ancillary data that sets the TOS byte of one outgoing datagram, so a shared
// reflector socket can answer each leg with that leg's own marking.
func tosControl(tos uint8) []byte {
	b := make([]byte, syscall.CmsgSpace(4))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = syscall.IPPROTO_IP, syscall.IP_TOS
	h.SetLen(syscall.CmsgLen(4))
	*(*int32)(unsafe.Pointer(&b[syscall.CmsgLen(0)])) = int32(tos)
	return b
}

// tcpInfo returns cumulative retransmitted segments and the kernel's smoothed RTT in microseconds.
func tcpInfo(c syscall.RawConn) (retrans uint32, srttUs uint32, ok bool) {
	_ = c.Control(func(fd uintptr) {
		var info syscall.TCPInfo
		size := uint32(unsafe.Sizeof(info))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&size)), 0)
		if errno == 0 {
			retrans, srttUs, ok = info.Total_retrans, info.Rtt, true
		}
	})
	return
}
