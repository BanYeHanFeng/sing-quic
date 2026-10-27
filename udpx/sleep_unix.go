//go:build linux || freebsd || openbsd || netbsd || dragonfly

package udpx

import (
	"syscall"
	"time"
)

// nanosleep waits for d and is late by about sixty microseconds whatever d is, which
// is what the pacing goroutine needs: the wait is asked for once per batch, so a
// clock that is late by a fixed amount is a clock the bucket can make up for.
//
// A signal ends the sleep early and the error is dropped: the caller asks the pacer
// again rather than sleeping a remainder worked out from a clock that has moved.
func nanosleep(d time.Duration) {
	remaining := syscall.NsecToTimespec(int64(d))
	_ = syscall.Nanosleep(&remaining, nil)
}
