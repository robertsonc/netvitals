//go:build windows

package main

import "syscall"

// setTOS attempts the classic IP_TOS socket option. Windows accepts the call but ignores the
// value unless QoS policy allows it, so marking cannot be confirmed from here: report false and
// let the dashboard say that DSCP on this endpoint needs a Windows QoS policy.
func setTOS(c syscall.RawConn, tos int) bool {
	_ = c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 3 /* IP_TOS */, tos)
	})
	return false
}
