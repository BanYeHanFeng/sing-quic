//go:build !(linux || freebsd || openbsd || netbsd || dragonfly)

package udpx

import (
	"time"
)

// nanosleep waits for d. What this end is built on has no sleep that is finer than
// the timer — darwin and windows only offer one through the C library — so pacing is
// no more precise than a timer is there, and a path that carries more than a batch
// per millisecond is paced in bursts of a millisecond on those platforms.
func nanosleep(d time.Duration) {
	time.Sleep(d)
}
