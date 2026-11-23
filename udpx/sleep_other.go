//go:build !(linux || freebsd || openbsd || netbsd || dragonfly)

package udpx

import (
	"time"
)

func nanosleep(d time.Duration) {
	time.Sleep(d)
}
