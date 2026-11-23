package congestion

import "cmp"

type windowedFilter[V any] struct {
	windowLength roundTripCount
	estimates    []entry[V]
	comparator   func(V, V) int
}

type entry[V any] struct {
	sample V
	time   roundTripCount
}

func maxFilter[O cmp.Ordered](a, b O) int {
	if a > b {
		return 1
	} else if a < b {
		return -1
	}
	return 0
}

func newWindowedFilter[V any](windowLength roundTripCount, comparator func(V, V) int) *windowedFilter[V] {
	return &windowedFilter[V]{
		windowLength: windowLength,
		estimates:    make([]entry[V], 3),
		comparator:   comparator,
	}
}

func (f *windowedFilter[V]) getBest() V {
	return f.estimates[0].sample
}

func (f *windowedFilter[V]) getSecondBest() V {
	return f.estimates[1].sample
}

func (f *windowedFilter[V]) getThirdBest() V {
	return f.estimates[2].sample
}

func (f *windowedFilter[V]) update(newSample V, newTime roundTripCount) {
	if f.comparator(f.estimates[0].sample, *new(V)) == 0 ||
		f.comparator(newSample, f.estimates[0].sample) >= 0 ||
		newTime-f.estimates[2].time > f.windowLength {
		f.reset(newSample, newTime)
		return
	}

	if f.comparator(newSample, f.estimates[1].sample) >= 0 {
		f.estimates[1] = entry[V]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
	} else if f.comparator(newSample, f.estimates[2].sample) >= 0 {
		f.estimates[2] = entry[V]{newSample, newTime}
	}

	if newTime-f.estimates[0].time > f.windowLength {
		f.estimates[0] = f.estimates[1]
		f.estimates[1] = f.estimates[2]
		f.estimates[2] = entry[V]{newSample, newTime}
		if newTime-f.estimates[0].time > f.windowLength {
			f.estimates[0] = f.estimates[1]
			f.estimates[1] = f.estimates[2]
		}
		return
	}
	if f.comparator(f.estimates[1].sample, f.estimates[0].sample) == 0 &&
		newTime-f.estimates[1].time > f.windowLength/4 {
		f.estimates[1] = entry[V]{newSample, newTime}
		f.estimates[2] = f.estimates[1]
		return
	}

	if f.comparator(f.estimates[2].sample, f.estimates[1].sample) == 0 &&
		newTime-f.estimates[2].time > f.windowLength/2 {
		f.estimates[2] = entry[V]{newSample, newTime}
	}
}

func (f *windowedFilter[V]) reset(newSample V, newTime roundTripCount) {
	f.estimates[2] = entry[V]{newSample, newTime}
	f.estimates[1] = f.estimates[2]
	f.estimates[0] = f.estimates[1]
}

func (f *windowedFilter[V]) clear() {
	f.estimates = make([]entry[V], 3)
}
