package udpx

const (
	initialStreamWindow = 512 * 1024

	initialConnectionWindow = 2 * 1024 * 1024

	streamWindow = 8 * 1024 * 1024

	connectionWindow = 16 * 1024 * 1024

	initialStreams = 256

	streamBudget = 4096
)

type credit struct {
	limit uint64
	used  uint64
}

func (c *credit) available() uint64 {
	if c.used >= c.limit {
		return 0
	}
	return c.limit - c.used
}

func (c *credit) take(n uint64) uint64 {
	available := c.available()
	if n > available {
		n = available
	}
	c.used += n
	return n
}

func (c *credit) give(limit uint64) bool {
	if limit <= c.limit {
		return false
	}
	c.limit = limit
	return true
}
