//go:build !linux

package main

import "syscall"

// Outside Linux there are no kernel receive timestamps, no TTL/TOS readback and no TCP_INFO:
// receive times are taken in user space right after the read returns, and replies say so.
const kernelRxStamps = false

func enableRxMeta(c syscall.RawConn) bool               { return false }
func parseRxMeta(oob []byte) (ts int64, ttl, tos uint8) { return 0, 0, 0 }
func tosControl(tos uint8) []byte                       { return nil }
func tcpInfo(c syscall.RawConn) (uint32, uint32, bool)  { return 0, 0, false }
