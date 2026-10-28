package udpx

import (
	"testing"
	"time"
)

// TestStreamChurn is the shape a proxy gives a session: open, one write, read it,
// close, many times over. Nothing else in the package ends a stream while it opens
// the next one, which is why this is where the stream table's races have shown up:
// a stream ending with frames still in flight, the ring that remembers the peer's
// streams, and the count of this end's own streams.
func TestStreamChurn(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 280*time.Second)
	count := 1000
	peer := make(chan error, 1)
	go func() {
		for range count {
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				peer <- err
				return
			}
			if _, err = readExactly(stream, 1); err != nil {
				peer <- err
				return
			}
			if err = stream.Close(); err != nil {
				peer <- err
				return
			}
		}
		peer <- nil
	}()
	start := time.Now()
	for index := range count {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatalf("client open %d: %v", index, err)
		}
		if _, err = stream.Write([]byte{0}); err != nil {
			t.Fatalf("client write %d: %v", index, err)
		}
		if err = stream.Close(); err != nil {
			t.Fatalf("client close %d: %v", index, err)
		}
	}
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	t.Logf("churn: %d connections in %v = %v each", count, elapsed.Round(time.Millisecond), elapsed/time.Duration(count))
}
