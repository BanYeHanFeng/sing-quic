package congestion

import "cmp"

// Implements Kathleen Nichols' algorithm for tracking the minimum (or maximum)
// estimate of a stream of samples over some fixed time interval. (E.g.,
// the minimum RTT over the past five minutes.) The algorithm keeps track of
// the best, second best, and third best min (or max) estimates, maintaining an
// invariant that the measurement time of the n'th best >= n-1'th best.

// The algorithm works as follows. On a reset, all three estimates are set to
// the same sample. The second best estimate is then recorded in the second
// quarter of the window, and a third best estimate is recorded in the second
// half of the window, bounding the worst case error when the true min is
// monotonically increasing (or true max is monotonically decreasing) over the
// window.
//
// A new best sample replaces all three estimates, since the new best is lower
// (or higher) than everything else in the window and it is the most recent.
// The window thus effectively gets reset on every new min. The same property
// holds true for second best and third best estimates. Specifically, when a
// sample arrives that is better than the second best but not better than the
// best, it replaces the second and third best estimates but not the best
// estimate. Similarly, a sample that is better than the third best estimate
// but not the other estimates replaces only the third best estimate.
//
// Finally, when the best expires, it is replaced by the second best, which in
// turn is replaced by the third best. The newest sample replaces the third
// best.

type WindowedFilter[V any] struct {
	// Time length of window.
	windowLength roundTripCount
	estimates    []entry[V]
	comparator   func(V, V) int
}

type entry[V any] struct {
	sample V
	time   roundTripCount
}

// Compares two values and returns true if the first is greater than or equal
// to the second.
func MaxFilter[O cmp.Ordered](a, b O) int {
	if a > b {
		return 1
	} else if a < b {
		return -1
	}
	return 0
}

func NewWindowedFilter[V any](windowLength roundTripCount, comparator func(V, V) int) *WindowedFilter[V] {
	return &WindowedFilter[V]{
		windowLength: windowLength,
		estimates:    make([]entry[V], 3),
		comparator:   comparator,
	}
}

func (f *WindowedFilter[V]) GetBest() V {
	return f.estimates[0].sample
}

func (f *WindowedFilter[V]) GetSecondBest() V {
	return f.estimates[1].sample
}

func (f *WindowedFilter[V]) GetThirdBest() V {
	return f.estimates[2].sample
}

// Updates best estimates with |sample|, and expires and updates best
// estimates as necessary.
func (f *WindowedFilter[V]) Update(newSample V, newTime roundTripCount) {
	// Reset all estimates if they have not yet been initialized, if new sample
	// is a new best, or if the newest recorded estimate is too old.
	if f.comparator(f.estimates[0].sample, *new(V)) == 0 ||
		f.comparator(newSample, f.estimates[0].sample) >= 0 ||
		newTime-f.estimates[2].time > f.windowLength {
		f.Reset(newSample, newTime)
		return
	}

	if f.comparator(newSample, f.estimates[1].sample) >= 0 {
		f.estimates[1] = entry[V]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
	} else if f.comparator(newSample, f.estimates[2].sample) >= 0 {
		f.estimates[2] = entry[V]{newSample, newTime}
	}

	// Expire and update estimates as necessary.
	if newTime-f.estimates[0].time > f.windowLength {
		// The best estimate hasn't been updated for an entire window, so promote
		// second and third best estimates.
		f.estimates[0] = f.estimates[1]
		f.estimates[1] = f.estimates[2]
		f.estimates[2] = entry[V]{newSample, newTime}
		// Need to iterate one more time. Check if the new best estimate is
		// outside the window as well, since it may also have been recorded a
		// long time ago. Don't need to iterate once more since we cover that
		// case at the beginning of the method.
		if newTime-f.estimates[0].time > f.windowLength {
			f.estimates[0] = f.estimates[1]
			f.estimates[1] = f.estimates[2]
		}
		return
	}
	if f.comparator(f.estimates[1].sample, f.estimates[0].sample) == 0 &&
		newTime-f.estimates[1].time > f.windowLength/4 {
		// A quarter of the window has passed without a better sample, so the
		// second-best estimate is taken from the second quarter of the window.
		f.estimates[1] = entry[V]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
		return
	}

	if f.comparator(f.estimates[2].sample, f.estimates[1].sample) == 0 &&
		newTime-f.estimates[2].time > f.windowLength/2 {
		// We've passed a half of the window without a better estimate, so take
		// a third-best estimate from the second half of the window.
		f.estimates[2] = entry[V]{newSample, newTime}
	}
}

// Resets all estimates to new sample.
func (f *WindowedFilter[V]) Reset(newSample V, newTime roundTripCount) {
	f.estimates[2] = entry[V]{newSample, newTime}
	f.estimates[1] = f.estimates[2]
	f.estimates[0] = f.estimates[1]
}

func (f *WindowedFilter[V]) Clear() {
	f.estimates = make([]entry[V], 3)
}
