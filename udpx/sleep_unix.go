//go:build linux || freebsd || openbsd || netbsd || dragonfly

package udpx

import (
	"syscall"
	"time"
)

func nanosleep(d time.Duration) {
	remaining := syscall.NsecToTimespec(int64(d))
	_ = syscall.Nanosleep(&remaining, nil)
}
