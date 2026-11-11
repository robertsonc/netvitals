//go:build !windows

package main

import "time"

// nowNs is the wall clock in nanoseconds. On Linux this is a vDSO clock_gettime(CLOCK_REALTIME),
// the same clock the kernel uses for SO_TIMESTAMPNS, so user and kernel stamps are comparable.
func nowNs() int64 { return time.Now().UnixNano() }

func clockSource() string { return "clock_gettime(CLOCK_REALTIME)" }

func tuneTimer() {}
