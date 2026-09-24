package qtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/bufio"
	aTLS "github.com/sagernet/sing/common/tls"
)

type testSTDServerConfig struct {
	aTLS.ServerConfig
	stdConfig *tls.Config
}

func (c *testSTDServerConfig) HandshakeTimeout() time.Duration {
	return 5 * time.Second
}

func (c *testSTDServerConfig) STDConfig() (*aTLS.STDConfig, error) {
	return c.stdConfig.Clone(), nil
}

type testXORPacketCodec struct {
	mask byte
}

func (c testXORPacketCodec) Encode(b []byte, write func(datagram []byte) error) error {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = v ^ c.mask
	}
	return write(out)
}

func (c testXORPacketCodec) Decode(b []byte, _ net.Addr) ([]byte, bool) {
	for i := range b {
		b[i] ^= c.mask
	}
	return b, true
}

func newTestSelfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"sing-quic-gso-test"},
	}
}

func runEchoAndObserveServerGSO(
	t *testing.T,
	serverAddr net.Addr,
	listener interface {
		Accept(context.Context) (*quic.Conn, error)
	},
	clientTLS *tls.Config,
	codec quic.PacketCodec,
	beforeDial func(),
) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	clientDone := make(chan struct{})
	var closeClientDoneOnce sync.Once
	closeClientDone := func() {
		closeClientDoneOnce.Do(func() {
			close(clientDone)
		})
	}
	defer closeClientDone()

	var serverGSO atomic.Bool
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.CloseWithError(0, "")
		serverGSO.Store(conn.ConnectionState().GSO)
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		_, err = io.Copy(stream, stream)
		if err != nil {
			serverErr <- err
			return
		}
		if err := stream.Close(); err != nil {
			serverErr <- err
			return
		}
		select {
		case <-clientDone:
		case <-ctx.Done():
		}
		serverErr <- nil
	}()

	if beforeDial != nil {
		beforeDial()
	}

	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	clientTr := &quic.Transport{Conn: clientUDP, PacketCodec: codec}
	defer clientTr.Close()

	clientConn, err := clientTr.Dial(ctx, serverAddr, clientTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.CloseWithError(0, "")

	stream, err := clientConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("hello-sing-quic-gso")
	if _, err := stream.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	closeClientDone()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected echo payload: got %q, want %q", got, want)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	return serverGSO.Load()
}

func measureNativeServerGSO(t *testing.T, serverTLS, clientTLS *tls.Config) bool {
	t.Helper()
	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverUDP.Close()

	serverTr := &quic.Transport{Conn: serverUDP}
	serverTr.SetSingleUse(true)
	listener, err := serverTr.Listen(serverTLS.Clone(), &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	return runEchoAndObserveServerGSO(t, serverUDP.LocalAddr(), listener, clientTLS, nil, nil)
}

func TestConfigWithGSO(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	wrapped := bufio.NewCounterConn(bufio.NewUDPConnWithoutGSO(udp), nil, nil)
	shared := &quic.Config{EnableDatagrams: true}
	configured := ConfigWithGSO(shared, wrapped)
	if !configured.DisableGSO || !configured.EnableDatagrams {
		t.Fatal("policy or existing config lost")
	}
	if shared.DisableGSO || configured == shared {
		t.Fatal("mutated a shared config")
	}
	if ConfigWithGSO(shared, udp) != shared {
		t.Fatal("changed unrestricted connection config")
	}
	if !ConfigWithGSO(nil, wrapped).DisableGSO {
		t.Fatal("nil config lost policy")
	}
	if ConfigWithGSO(nil, udp) != nil {
		t.Fatal("unrestricted nil config changed")
	}
	ApplyQUICOptions(shared, QUICOptions{DisableGSO: true})
	ApplyQUICOptions(shared, QUICOptions{})
	if !shared.DisableGSO {
		t.Fatal("overrode an existing prohibition")
	}
}

func TestListenWithOptionsGSO(t *testing.T) {
	serverTLS := &testSTDServerConfig{stdConfig: newTestSelfSignedTLSConfig(t)}
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"sing-quic-gso-test"},
	}
	probePayload := []byte("STUN-PROBE-INTERCEPT")

	nativeGSO := measureNativeServerGSO(t, serverTLS.stdConfig, clientTLS)
	t.Logf("native quic.Transport server GSO=%v", nativeGSO)

	// Reuse the same *quic.Config across restricted and unrestricted listeners
	// with HandshakeIdleTimeout pre-populated to ensure per-listener GSO
	// restriction never leaks to subsequent callers.
	sharedCfg := &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: 5 * time.Second,
	}

	for _, tc := range []struct {
		name           string
		disableSocket  bool
		useCodec       bool
		useInterceptor bool
		expectGSO      bool
	}{
		{name: "plain-restricted", disableSocket: true, expectGSO: false},
		{name: "plain-unrestricted", disableSocket: false, expectGSO: nativeGSO},
		{name: "codec-unrestricted", useCodec: true, expectGSO: false},
		{name: "interceptor-only-restricted", disableSocket: true, useInterceptor: true, expectGSO: false},
		{name: "interceptor-only-unrestricted", useInterceptor: true, expectGSO: nativeGSO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer serverUDP.Close()

			var serverConn net.PacketConn = serverUDP
			if tc.disableSocket {
				serverConn = bufio.NewUDPConnWithoutGSO(serverUDP)
			}
			var options ListenOptions
			var codec quic.PacketCodec
			var intercepted atomic.Int32
			if tc.useCodec {
				codec = testXORPacketCodec{mask: 0x5a}
				options.PacketCodec = codec
			}
			if tc.useInterceptor {
				options.PacketInterceptor = func(b []byte, _ net.Addr) bool {
					if bytes.Equal(b, probePayload) {
						intercepted.Add(1)
						return true
					}
					return false
				}
			}
			listener, err := ListenWithOptions(serverConn, serverTLS, sharedCfg, options)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if sharedCfg.DisableGSO {
				t.Fatal("ListenWithOptions mutated shared quic.Config")
			}

			var beforeDial func()
			if tc.useInterceptor {
				beforeDial = func() {
					probeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					defer probeConn.Close()
					if _, err := probeConn.WriteTo(probePayload, serverUDP.LocalAddr()); err != nil {
						t.Fatal(err)
					}
				}
			}

			gotGSO := runEchoAndObserveServerGSO(t, serverUDP.LocalAddr(), listener, clientTLS, codec, beforeDial)
			if gotGSO != tc.expectGSO {
				t.Fatalf("server GSO=%v, want %v (native=%v)", gotGSO, tc.expectGSO, nativeGSO)
			}
			if tc.useInterceptor && intercepted.Load() == 0 {
				t.Fatal("expected PacketInterceptor to consume probe packet")
			}
		})
	}
}
