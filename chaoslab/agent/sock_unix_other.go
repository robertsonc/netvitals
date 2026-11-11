//go:build !linux && !windows

package main

import "syscall"

func setTOS(c syscall.RawConn, tos int) bool {
	ok := false
	_ = c.Control(func(fd uintptr) {
		ok = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos) == nil
	})
	return ok
}
