package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-quic/udpx"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "udpxbench:", err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "server", "server or client")
	listen := flag.String("listen", ":30021", "address the server listens on")
	server := flag.String("server", "127.0.0.1:30021", "address the client connects to")
	password := flag.String("password", "udpxbench", "shared password")
	streamMode := flag.Bool("stream", false, "move a stream instead of datagrams")
	size := flag.Int("size", 1200, "datagram payload size, or stream size in MiB")
	pps := flag.Int("pps", 1000, "datagrams per second")
	duration := flag.Duration("duration", 30*time.Second, "how long the client runs")
	mtu := flag.Int("mtu", 0, "packet size limit, zero to discover it")
	debug := flag.Bool("debug", false, "print the transport's own log")
	flag.Parse()

	options := udpx.Options{
		IdleTimeout:     time.Minute,
		KeepAlivePeriod: 10 * time.Second,
		MTU:             *mtu,
	}
	if *debug {
		options.Logger = stdLogger{}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	switch *mode {
	case "server":
		return runServer(ctx, *listen, *password, options, *streamMode)
	case "client":
		return runClient(ctx, *server, *password, options, *streamMode, *size, *pps, *duration)
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
}

func runServer(ctx context.Context, listen, password string, options udpx.Options, streamMode bool) error {
	conn, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	listener := udpx.Listen(conn, passwordVerifier{credential: udpx.NewCredential(password)}, options)
	defer listener.Close()
	fmt.Println("listening on", conn.LocalAddr())
	for {
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			return acceptErr
		}
		go serveAssociation(ctx, conn, streamMode)
	}
}

func serveAssociation(ctx context.Context, conn *udpx.Conn, streamMode bool) {
	if streamMode {
		for {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, stream)
				_ = stream.Close()
			}()
		}
	}
	for {
		datagram, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if err = conn.SendDatagram(datagram); err != nil {
			return
		}
	}
}

const datagramHeaderLen = 8 + 8

func runClient(ctx context.Context, server, password string, options udpx.Options, streamMode bool, size, pps int, duration time.Duration) error {
	remote, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return err
	}
	socket, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	conn, err := udpx.Dial(ctx, socket, remote, udpx.NewCredential(password), options)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(nil)
	fmt.Println("connected to", remote)
	if streamMode {
		return runStream(ctx, conn, size, duration)
	}
	return runDatagrams(ctx, conn, size, pps, duration)
}

type measurement struct {
	sent     atomic.Int64
	received atomic.Int64
	bytes    atomic.Int64
	mu       sync.Mutex
	latency  []time.Duration
}

func (m *measurement) record(sentAt time.Time) {
	m.received.Add(1)
	m.bytes.Add(datagramHeaderLen + 0)
	m.mu.Lock()
	m.latency = append(m.latency, time.Since(sentAt))
	m.mu.Unlock()
}

func (m *measurement) summary(elapsed time.Duration) string {
	sent := m.sent.Load()
	received := m.received.Load()
	loss := 0.0
	if sent > 0 {
		loss = 100 * float64(sent-received) / float64(sent)
	}
	m.mu.Lock()
	latency := append([]time.Duration(nil), m.latency...)
	m.mu.Unlock()
	sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
	pick := func(fraction float64) time.Duration {
		if len(latency) == 0 {
			return 0
		}
		index := int(fraction * float64(len(latency)-1))
		return latency[index]
	}
	average := time.Duration(0)
	if len(latency) > 0 {
		average = latencySum(latency) / time.Duration(len(latency))
	}
	return fmt.Sprintf("sent=%d received=%d loss=%.2f%% rtt min/avg/p99=%v/%v/%v",
		sent, received, loss, pick(0).Round(time.Microsecond),
		average.Round(time.Microsecond), pick(0.99).Round(time.Microsecond))
}

func latencySum(latency []time.Duration) time.Duration {
	var total time.Duration
	for _, value := range latency {
		total += value
	}
	return total
}

func runDatagrams(ctx context.Context, conn *udpx.Conn, size, pps int, duration time.Duration) error {
	if size < datagramHeaderLen {
		return fmt.Errorf("datagram size %d is below the %d byte header", size, datagramHeaderLen)
	}
	measure := &measurement{}
	payload := make([]byte, size)
	interval := time.Second / time.Duration(max(pps, 1))
	start := time.Now()
	deadline := start.Add(duration)
	var sequence uint64

	go func() {
		for {
			datagram, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			if len(datagram) < datagramHeaderLen {
				continue
			}
			at := time.Unix(0, int64(binary.BigEndian.Uint64(datagram[8:])))
			measure.record(at)
		}
	}()
	next := start
	for time.Now().Before(deadline) {
		binary.BigEndian.PutUint64(payload[:8], sequence)
		binary.BigEndian.PutUint64(payload[8:], uint64(time.Now().UnixNano()))
		sequence++
		if err := conn.SendDatagram(payload); err != nil {
			return err
		}
		measure.sent.Add(1)
		next = next.Add(interval)
		if wait := time.Until(next); wait > 0 {
			time.Sleep(wait)
		} else {
			next = time.Now()
		}
	}
	time.Sleep(time.Second)
	fmt.Println(measure.summary(time.Since(start)))
	return nil
}

func runStream(ctx context.Context, conn *udpx.Conn, sizeMiB int, duration time.Duration) error {
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return err
	}
	total := int64(sizeMiB) << 20
	chunk := make([]byte, 32<<10)
	rand.Read(chunk)
	start := time.Now()
	written := int64(0)
	for written < total {
		if err = stream.SetWriteDeadline(start.Add(duration)); err != nil {
			return err
		}
		n, writeErr := stream.Write(chunk)
		written += int64(n)
		if writeErr != nil {
			return writeErr
		}
	}
	if err = stream.CloseWrite(); err != nil {
		return err
	}
	if _, err = io.Copy(io.Discard, stream); err != nil {
		return err
	}
	elapsed := time.Since(start)
	fmt.Printf("wrote %d bytes in %v: %.2f MiB/s\n", written, elapsed.Round(time.Millisecond),
		float64(written)/elapsed.Seconds()/(1<<20))
	return nil
}

type passwordVerifier struct {
	credential udpx.Credential
}

func (v passwordVerifier) Lookup(keyID [8]byte) (udpx.Credential, bool) {
	if keyID != v.credential.KeyID() {
		return udpx.Credential{}, false
	}
	return v.credential, true
}

type stdLogger struct{}

func (stdLogger) Trace(args ...any) {}
func (stdLogger) Debug(args ...any) { fmt.Println(append([]any{"[debug]"}, args...)...) }
func (stdLogger) Info(args ...any)  { fmt.Println(append([]any{"[info]"}, args...)...) }
func (stdLogger) Warn(args ...any)  { fmt.Println(append([]any{"[warn]"}, args...)...) }
func (stdLogger) Error(args ...any) { fmt.Println(append([]any{"[error]"}, args...)...) }
func (stdLogger) Fatal(args ...any) { fmt.Println(append([]any{"[fatal]"}, args...)...) }
func (stdLogger) Panic(args ...any) { fmt.Println(append([]any{"[panic]"}, args...)...) }
