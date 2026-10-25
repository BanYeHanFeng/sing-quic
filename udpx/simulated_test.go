package udpx

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// transferBounds is what the state of one end looked like while a transfer ran. The
// point of sampling it is that the bound is a property of the transfer and not of
// the moment it ended: an unbounded queue or an unbounded reassembly looks fine
// again as soon as it is empty.
type transferBounds struct {
	streams        int
	inFlightBytes  int
	queuedFrames   int
	streamSegments int
	reassembly     int
}

// sampleBounds reads the state of one end, one lock at a time.
func sampleBounds(association *association) transferBounds {
	association.streamsMu.Lock()
	streams := make([]*Stream, 0, len(association.streams))
	for _, stream := range association.streams {
		streams = append(streams, stream)
	}
	association.streamsMu.Unlock()
	association.flightMu.Lock()
	inFlightBytes := association.inFlight.bytes
	association.flightMu.Unlock()
	association.sendMu.Lock()
	queuedFrames := association.queue.len()
	association.sendMu.Unlock()
	association.datagramMu.Lock()
	reassembly := association.defragger.bytes
	association.datagramMu.Unlock()
	streamSegments := 0
	for _, stream := range streams {
		stream.recvMu.Lock()
		for _, segment := range stream.segments {
			streamSegments += len(segment.data)
		}
		stream.recvMu.Unlock()
	}
	return transferBounds{
		streams:        len(streams),
		inFlightBytes:  inFlightBytes,
		queuedFrames:   queuedFrames,
		streamSegments: streamSegments,
		reassembly:     reassembly,
	}
}

// boundsSampler records the largest value each bound reached while it ran.
type boundsSampler struct {
	mu     sync.Mutex
	worst  transferBounds
	stopCh chan struct{}
	done   chan struct{}
}

func startBoundsSampler(t *testing.T, associations ...Association) *boundsSampler {
	t.Helper()
	sampler := &boundsSampler{
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
	go func() {
		defer close(sampler.done)
		for {
			select {
			case <-sampler.stopCh:
				return
			case <-time.After(5 * time.Millisecond):
			}
			for _, conn := range associations {
				bounds := sampleBounds(conn.(*association))
				sampler.mu.Lock()
				sampler.worst.streams = max(sampler.worst.streams, bounds.streams)
				sampler.worst.inFlightBytes = max(sampler.worst.inFlightBytes, bounds.inFlightBytes)
				sampler.worst.queuedFrames = max(sampler.worst.queuedFrames, bounds.queuedFrames)
				sampler.worst.streamSegments = max(sampler.worst.streamSegments, bounds.streamSegments)
				sampler.worst.reassembly = max(sampler.worst.reassembly, bounds.reassembly)
				sampler.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() {
		close(sampler.stopCh)
		<-sampler.done
	})
	return sampler
}

func (s *boundsSampler) worstBounds() transferBounds {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.worst
}

// otherPayload is a payload that is not the one testPayload builds, so that data
// going the other way cannot be mistaken for data going this way.
func otherPayload(size int) []byte {
	payload := testPayload(size)
	for index := range payload {
		payload[index] ^= 0xa5
	}
	return payload
}

// readExactly reads size bytes, reporting an error instead of ending the calling
// goroutine: the goroutines of a transfer have to report what went wrong to the
// test, and a t.Fatal in one of them leaves the others waiting.
func readExactly(stream *Stream, size int) ([]byte, error) {
	read := make([]byte, 0, size)
	buffer := make([]byte, 32*1024)
	for len(read) < size {
		n, err := stream.Read(buffer)
		if err != nil {
			return read, err
		}
		read = append(read, buffer[:n]...)
	}
	return read, nil
}

// readToEnd reads size bytes and then the end of the stream, and closes it. A
// stream is released on both ends once each end closed its half, so a transfer
// that reads what it was sent has to say that it is done reading.
func readToEnd(stream *Stream, size int) ([]byte, error) {
	read, err := readExactly(stream, size)
	if err != nil {
		return read, err
	}
	n, err := stream.Read(make([]byte, 1))
	if n != 0 || err != io.EOF {
		return read, E.New("the stream ended with ", n, " bytes and ", err)
	}
	if closeErr := stream.Close(); closeErr != nil {
		return read, closeErr
	}
	return read, nil
}

// waitGroup waits for work to finish and fails the test instead of hanging if it
// does not, which is what turns a deadlock into a failure with a name.
func waitGroup(t *testing.T, group *sync.WaitGroup, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal("the transfer did not finish")
	}
}

// TestTransferOverSimulatedPath requires a transfer in both directions at once to
// arrive intact over a path of 200 ms with loss, duplication and reordering, the
// datagrams of the same association to survive it, and the state of both ends to
// stay bounded while it happens.
//
// The bounds are the invariants of the transport: bytes in flight and frames
// queued follow the windows, what waits to be read follows the stream window, and a
// datagram reassembly follows its own limit. A transfer that completes with any of
// them growing without a ceiling is a leak that a slower path turns into an
// out-of-memory.
func TestTransferOverSimulatedPath(t *testing.T) {
	const payloadSize = 512 * 1024
	const datagramCount = 32
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{
		loss:      0.02,
		duplicate: 0.02,
		delay:     100 * time.Millisecond,
		jitter:    30 * time.Millisecond,
	})

	ctx := testContext(t, 240*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(nil)

	sampler := startBoundsSampler(t, client, server)
	upload := testPayload(payloadSize)
	download := otherPayload(payloadSize)
	datagramPayload := testPayload(2 * datagramFragmentLen)
	var wg sync.WaitGroup

	// This way: the client opens a stream and the server reads it.
	wg.Add(2)
	go func() {
		defer wg.Done()
		stream, openErr := client.OpenStream(ctx)
		if openErr != nil {
			t.Errorf("open the upload: %v", openErr)
			return
		}
		if _, writeErr := stream.Write(upload); writeErr != nil {
			t.Errorf("upload: %v", writeErr)
			return
		}
		if closeErr := stream.CloseWrite(); closeErr != nil {
			t.Errorf("close the upload: %v", closeErr)
		}
	}()
	go func() {
		defer wg.Done()
		stream, acceptErr := server.AcceptStream(ctx)
		if acceptErr != nil {
			t.Errorf("accept the upload: %v", acceptErr)
			return
		}
		read, readErr := readToEnd(stream, len(upload))
		if readErr != nil {
			t.Errorf("the upload stopped after %d bytes: %v", len(read), readErr)
			return
		}
		if !bytes.Equal(read, upload) {
			t.Error("the upload changed on the way")
		}
	}()

	// And the other way, on a stream the server opens.
	wg.Add(2)
	go func() {
		defer wg.Done()
		stream, openErr := server.OpenStream(ctx)
		if openErr != nil {
			t.Errorf("open the download: %v", openErr)
			return
		}
		if _, writeErr := stream.Write(download); writeErr != nil {
			t.Errorf("download: %v", writeErr)
			return
		}
		if closeErr := stream.CloseWrite(); closeErr != nil {
			t.Errorf("close the download: %v", closeErr)
		}
	}()
	go func() {
		defer wg.Done()
		stream, acceptErr := client.AcceptStream(ctx)
		if acceptErr != nil {
			t.Errorf("accept the download: %v", acceptErr)
			return
		}
		read, readErr := readToEnd(stream, len(download))
		if readErr != nil {
			t.Errorf("the download stopped after %d bytes: %v", len(read), readErr)
			return
		}
		if !bytes.Equal(read, download) {
			t.Error("the download changed on the way")
		}
	}()

	// Datagrams share the association with both transfers, which is what a
	// forwarded UDP packet does while a proxied connection runs beside it. Some of
	// them are lost with a fragment, so what arrives is checked and counted, not
	// required to be all of them.
	datagramCtx, stopDatagrams := context.WithCancel(ctx)
	arrivedDatagrams := make(chan int, 1)
	go func() {
		arrived := 0
		for {
			datagram, receiveErr := server.ReceiveDatagram(datagramCtx)
			if receiveErr != nil {
				arrivedDatagrams <- arrived
				return
			}
			if datagram.Channel != 3 || !bytes.Equal(datagram.Data, datagramPayload) {
				t.Errorf("a datagram on channel %d changed on the way", datagram.Channel)
				arrivedDatagrams <- arrived
				return
			}
			arrived++
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for index := 0; index < datagramCount; index++ {
			// A message larger than a packet, so the fragments have to be
			// reassembled while the streams are moving.
			if sendErr := client.SendDatagram(3, datagramPayload); sendErr != nil {
				t.Errorf("datagram %d: %v", index, sendErr)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	waitGroup(t, &wg, 120*time.Second)
	// What is still on the way belongs to the datagrams, since the streams are
	// done: the delay of the path is what has to pass.
	time.Sleep(time.Second)
	stopDatagrams()
	arrived := <-arrivedDatagrams
	if arrived == 0 {
		t.Error("not one datagram arrived")
	}
	if arrived > datagramCount {
		t.Errorf("%d datagrams arrived of %d sent", arrived, datagramCount)
	}

	bounds := sampler.worstBounds()
	if bounds.streams > maxStreams {
		t.Errorf("%d streams were open at once", bounds.streams)
	}
	if bounds.inFlightBytes > 2*initialConnectionWindow {
		t.Errorf("%d bytes were in flight at once", bounds.inFlightBytes)
	}
	// A stream may queue what its window allows, and the frames of the other
	// stream and of the association go beside it.
	if frames := bounds.queuedFrames; frames > 8*(initialStreamWindow/maxStreamDataLen) {
		t.Errorf("%d frames were queued at once", frames)
	}
	if bounds.streamSegments > 2*initialStreamWindow {
		t.Errorf("%d bytes were waiting to be read on the streams at once", bounds.streamSegments)
	}
	if bounds.reassembly > maxDatagramReassemblyBytes {
		t.Errorf("%d bytes of datagrams were reassembled at once", bounds.reassembly)
	}
	// Nothing of the streams is left: both ended and both were released.
	if count := streamCount(t, client); count != 0 {
		t.Errorf("%d streams are left on the client", count)
	}
	if count := streamCount(t, server); count != 0 {
		t.Errorf("%d streams are left on the server", count)
	}
}

// TestStreamBothDirectionsBlocked requires the credit a read grants to reach the
// writer of the same stream, while the reader of that stream is waiting for data
// that will not come. Both halves of one stream wait at the same time, so one
// notification channel for both of them delivers the credit to the reader: the
// writer then waits for credit that already arrived, and nothing else ever happens
// to wake it.
func TestStreamBothDirectionsBlocked(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 120*time.Second)
	for round := range 8 {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// A stream exists on the peer only once something was written on it.
		_, err = stream.Write([]byte{0})
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if read, readErr := readExactly(accepted, 1); readErr != nil || read[0] != 0 {
			t.Fatalf("round %d: the first byte is %v, %v", round, read, readErr)
		}
		// The writer fills the whole window and has a few bytes left over, so it
		// is waiting for credit when the peer reads.
		payload := testPayload(initialStreamWindow + 4096)
		written := make(chan error, 1)
		go func() {
			_, writeErr := stream.Write(payload)
			written <- writeErr
		}()
		// The reader of the same stream waits for data that never comes.
		readStarted := make(chan struct{})
		go func() {
			close(readStarted)
			_, _ = stream.Read(make([]byte, 1024))
		}()
		<-readStarted
		time.Sleep(20 * time.Millisecond)
		// Reading grants the credit, and it is the last thing that happens on this
		// stream: the peer reads exactly what it was sent and stops.
		if read, readErr := readExactly(accepted, len(payload)); readErr != nil {
			t.Fatalf("round %d: the peer read %d bytes: %v", round, len(read), readErr)
		}
		select {
		case err = <-written:
			if err != nil {
				t.Fatalf("round %d: the write ended with %v", round, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: the writer waited for credit that arrived", round)
		}
		_ = stream.Close()
		_ = accepted.Close()
	}
}

// TestAssociationEndsUnderLoad requires an association that ends while both ends
// are still transferring to end for both of them: a reader and a writer that wait
// for a window have to see it, or the close of one end leaves the other running.
func TestAssociationEndsUnderLoad(t *testing.T) {
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{delay: 20 * time.Millisecond})

	ctx := testContext(t, 60*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		// More than the windows allow, so the write is waiting for credit when
		// the association goes away.
		_, writeErr := stream.Write(testPayload(2 * initialConnectionWindow))
		writeDone <- writeErr
	}()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = accepted.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	err = server.CloseWithError(nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-writeDone:
		if err == nil {
			t.Fatal("the write finished after the association ended")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the write waited for an association that ended")
	}
	select {
	case <-client.Context().Done():
	case <-time.After(30 * time.Second):
		t.Fatal("the client did not notice that the peer closed")
	}
	if _, err = accepted.Read(make([]byte, 1)); err == nil {
		t.Fatal("a stream of an ended association still reads")
	}
	if _, err = stream.Write([]byte("more")); err == nil {
		t.Fatal("a stream of an ended association still writes")
	}
}
