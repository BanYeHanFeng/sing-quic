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

func otherPayload(size int) []byte {
	payload := testPayload(size)
	for index := range payload {
		payload[index] ^= 0xa5
	}
	return payload
}

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

func TestTransferOverSimulatedPath(t *testing.T) {
	const payloadSize = 512 * 1024
	const datagramCount = 32
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener := Listen(listenerConn, testVerifier{credential: credential}, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{
		loss:       0.02,
		lossReturn: 0.02,
		duplicate:  0.02,
		delay:      100 * time.Millisecond,
		jitter:     30 * time.Millisecond,
	})

	ctx := testContext(t, 240*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), credential, Options{MTU: mtuIPv4})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(nil)

	upload := testPayload(payloadSize)
	download := otherPayload(payloadSize)
	datagramPayload := testPayload(2 * (mtuIPv4 - headerLen - tagLen - datagramHeaderLen))
	var wg sync.WaitGroup

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
			if sendErr := client.SendDatagram(3, datagramPayload); sendErr != nil {
				t.Errorf("datagram %d: %v", index, sendErr)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	waitGroup(t, &wg, 120*time.Second)
	time.Sleep(time.Second)
	stopDatagrams()
	arrived := <-arrivedDatagrams
	if arrived == 0 {
		t.Error("not one datagram arrived")
	}
	if arrived > datagramCount {
		t.Errorf("%d datagrams arrived of %d sent", arrived, datagramCount)
	}

}

func TestStreamBothDirectionsBlocked(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 120*time.Second)
	for round := range 8 {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
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
		payload := testPayload(2*streamWindow + 4096)
		written := make(chan error, 1)
		go func() {
			_, writeErr := stream.Write(payload)
			written <- writeErr
		}()
		readStarted := make(chan struct{})
		go func() {
			close(readStarted)
			_, _ = stream.Read(make([]byte, 1024))
		}()
		<-readStarted
		time.Sleep(20 * time.Millisecond)
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

func TestAssociationEndsUnderLoad(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener := Listen(listenerConn, testVerifier{credential: credential}, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{delay: 20 * time.Millisecond})

	ctx := testContext(t, 60*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), credential, Options{MTU: mtuIPv4})
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
		_, writeErr := stream.Write(testPayload(2*streamWindow + 4096))
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
			t.Fatal("the write finished after the connection ended")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the write waited for a connection that ended")
	}
	select {
	case <-client.Context().Done():
	case <-time.After(30 * time.Second):
		t.Fatal("the client did not notice that the peer closed")
	}
	if _, err = accepted.Read(make([]byte, 1)); err == nil {
		t.Fatal("a stream of an ended connection still reads")
	}
	if _, err = stream.Write([]byte("more")); err == nil {
		t.Fatal("a stream of an ended connection still writes")
	}
}
