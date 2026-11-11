//go:build windows

package main

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32    = syscall.NewLazyDLL("kernel32.dll")
	procPrecise = kernel32.NewProc("GetSystemTimePreciseAsFileTime")
	winmm       = syscall.NewLazyDLL("winmm.dll")
	procPeriod  = winmm.NewProc("timeBeginPeriod")
	havePrecise = procPrecise.Find() == nil
)

// nowNs is the wall clock in nanoseconds. time.Now() on Windows only advances with the system
// timer tick (0.5 to 15.6 ms), which would quantise every measurement, so read the precise
// system time (QueryPerformanceCounter-interpolated, sub-microsecond, Windows 8 and later).
func nowNs() int64 {
	if !havePrecise {
		return time.Now().UnixNano()
	}
	var ft syscall.Filetime
	procPrecise.Call(uintptr(unsafe.Pointer(&ft)))
	return ft.Nanoseconds()
}

func clockSource() string {
	if havePrecise {
		return "GetSystemTimePreciseAsFileTime"
	}
	return "time.Now (coarse: timer-tick resolution)"
}

// tuneTimer asks for 1 ms scheduler granularity so paced sends are not bunched on 15.6 ms ticks.
func tuneTimer() {
	if procPeriod.Find() == nil {
		procPeriod.Call(1)
	}
}
