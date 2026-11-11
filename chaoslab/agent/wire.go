package main

import (
	"encoding/binary"
	"errors"
)

// Data-plane wire format, shared by UDP datagrams and length-prefixed TCP messages.
// All integers are big-endian. Timestamps are wall-clock nanoseconds since the Unix epoch
// on the host that wrote them; the two hosts' clocks are never compared directly.
//
//	 0  magic  u32  "CLB1"
//	 4  type   u8   1 probe, 2 reply, 3 TCP hello
//	 5  flags  u8
//	 6  rsvd   u16
//	 8  leg    u32  controller-assigned id of this sender->reflector session
//	12  seq    u32
//	16  t1     i64  sender: just before the packet is handed to the kernel
//	24  t2     i64  reflector: receive time (kernel stamp when FlagKernelTS is set)
//	32  t3     i64  reflector: just before the reply is handed to the kernel
//	40  rxttl  u8   IP TTL the probe arrived with (0 = unknown)
//	41  rxtos  u8   IP TOS byte the probe arrived with
//	42  rsvd   u16
//	44  padding to the configured packet size (pseudorandom, so WAN optimisation cannot compress it)
const (
	magic  = 0x434C4231
	hdrLen = 44

	typeProbe = 1
	typeReply = 2
	typeHello = 3

	flagKernelTS = 1 << 0 // reply: t2 is a kernel receive timestamp
	flagMinEcho  = 1 << 1 // probe: reply with the header only

	maxPacket = 9000
)

type header struct {
	Type, Flags  uint8
	Leg, Seq     uint32
	T1, T2, T3   int64
	RxTTL, RxTOS uint8
}

var errBadPacket = errors.New("not a chaoslab packet")

func (h *header) put(b []byte) {
	binary.BigEndian.PutUint32(b[0:], magic)
	b[4], b[5], b[6], b[7] = h.Type, h.Flags, 0, 0
	binary.BigEndian.PutUint32(b[8:], h.Leg)
	binary.BigEndian.PutUint32(b[12:], h.Seq)
	binary.BigEndian.PutUint64(b[16:], uint64(h.T1))
	binary.BigEndian.PutUint64(b[24:], uint64(h.T2))
	binary.BigEndian.PutUint64(b[32:], uint64(h.T3))
	b[40], b[41], b[42], b[43] = h.RxTTL, h.RxTOS, 0, 0
}

func (h *header) parse(b []byte) error {
	if len(b) < hdrLen || binary.BigEndian.Uint32(b[0:]) != magic {
		return errBadPacket
	}
	h.Type, h.Flags = b[4], b[5]
	h.Leg = binary.BigEndian.Uint32(b[8:])
	h.Seq = binary.BigEndian.Uint32(b[12:])
	h.T1 = int64(binary.BigEndian.Uint64(b[16:]))
	h.T2 = int64(binary.BigEndian.Uint64(b[24:]))
	h.T3 = int64(binary.BigEndian.Uint64(b[32:]))
	h.RxTTL, h.RxTOS = b[40], b[41]
	return nil
}

// fillPadding writes cheap pseudorandom bytes (xorshift) after the header.
func fillPadding(b []byte, seed uint64) {
	x := seed | 1
	for i := hdrLen; i < len(b); i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x)
	}
}
