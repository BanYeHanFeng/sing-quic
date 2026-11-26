package qtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	aTLS "github.com/sagernet/sing/common/tls"
)

const chromeTrustAnchorsExt uint16 = 0xca34

type testSTDClientConfig struct {
	aTLS.Config
	stdConfig *tls.Config
}

func (c *testSTDClientConfig) HandshakeTimeout() time.Duration {
	return 5 * time.Second
}

func (c *testSTDClientConfig) STDConfig() (*aTLS.STDConfig, error) {
	return c.stdConfig, nil
}

type observedHello struct {
	serverName string
	extensions []uint16
}

type observedAuth struct {
	host       string
	path       string
	negotiated string
}

func newHTTP3TestCert(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-quic-test-root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return tls.Certificate{
		Certificate: [][]byte{leafDER, rootDER},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}, pool
}

func startHTTP3AuthServer(t *testing.T, cert tls.Certificate) (*net.UDPAddr, <-chan observedHello, <-chan observedAuth, *atomic.Int32) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	helloCh := make(chan observedHello, 8)
	authCh := make(chan observedAuth, 8)
	var authCount atomic.Int32

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case helloCh <- observedHello{
				serverName: chi.ServerName,
				extensions: slices.Clone(chi.Extensions),
			}:
			default:
			}
			return nil, nil
		},
	}
	tr := &quic.Transport{Conn: udpConn}
	tr.SetSingleUse(true)
	ln, err := tr.ListenEarly(serverTLS, &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		_ = tr.Close()
		_ = udpConn.Close()
		t.Fatal(err)
	}

	h3Server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCount.Add(1)
			negotiated := ""
			if r.TLS != nil {
				negotiated = r.TLS.NegotiatedProtocol
			}
			select {
			case authCh <- observedAuth{
				host:       r.Host,
				path:       r.URL.Path,
				negotiated: negotiated,
			}:
			default:
			}
			w.WriteHeader(233)
		}),
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = h3Server.ServeListener(ln)
	})
	t.Cleanup(func() {
		_ = h3Server.Close()
		_ = ln.Close()
		_ = tr.Close()
		_ = udpConn.Close()
		wg.Wait()
	})
	return udpConn.LocalAddr().(*net.UDPAddr), helloCh, authCh, &authCount
}

func readObservedHello(t *testing.T, ch <-chan observedHello) observedHello {
	t.Helper()
	select {
	case hello := <-ch:
		return hello
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ClientHello")
		return observedHello{}
	}
}

func readObservedAuth(t *testing.T, ch <-chan observedAuth) observedAuth {
	t.Helper()
	select {
	case auth := <-ch:
		return auth
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 auth request")
		return observedAuth{}
	}
}

func TestHTTP3TransportServerName(t *testing.T) {
	cert, roots := newHTTP3TestCert(t, "cert.example")

	factories := []struct {
		name   string
		create func(t *testing.T, addr *net.UDPAddr, cfg aTLS.Config, qcfg *quic.Config) (http.RoundTripper, **quic.Conn, func())
	}{
		{
			name: "CreateTransport",
			create: func(t *testing.T, addr *net.UDPAddr, cfg aTLS.Config, qcfg *quic.Config) (http.RoundTripper, **quic.Conn, func()) {
				udpConn, err := net.DialUDP("udp4", nil, addr)
				if err != nil {
					t.Fatal(err)
				}
				var quicConn *quic.Conn
				rt, err := CreateTransport(udpConn, &quicConn, cfg, qcfg)
				if err != nil {
					_ = udpConn.Close()
					t.Fatal(err)
				}
				cleanup := func() {
					if quicConn != nil {
						_ = quicConn.CloseWithError(0, "")
					}
					_ = udpConn.Close()
				}
				return rt, &quicConn, cleanup
			},
		},
		{
			name: "CreatePacketTransport",
			create: func(t *testing.T, addr *net.UDPAddr, cfg aTLS.Config, qcfg *quic.Config) (http.RoundTripper, **quic.Conn, func()) {
				udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				var quicConn *quic.Conn
				rt, err := CreatePacketTransport(udpConn, addr, &quicConn, cfg, qcfg)
				if err != nil {
					_ = udpConn.Close()
					t.Fatal(err)
				}
				cleanup := func() {
					if quicConn != nil {
						_ = quicConn.CloseWithError(0, "")
					}
					_ = udpConn.Close()
				}
				return rt, &quicConn, cleanup
			},
		},
	}

	for _, factory := range factories {
		t.Run(factory.name, func(t *testing.T) {
			t.Run("empty SNI preserved with ChromeParrot and VerifyConnection", func(t *testing.T) {
				addr, helloCh, authCh, _ := startHTTP3AuthServer(t, cert)

				var verifyCalled atomic.Bool
				baseTLS := &tls.Config{
					ServerName:         "",
					InsecureSkipVerify: true,
					NextProtos:         []string{"custom-alpn"},
					VerifyConnection: func(state tls.ConnectionState) error {
						verifyCalled.Store(true)
						if state.ServerName != "" {
							return errors.New("unexpected non-empty ServerName in VerifyConnection")
						}
						if len(state.PeerCertificates) == 0 || !state.PeerCertificates[0].Equal(cert.Leaf) {
							return errors.New("unexpected peer certificate")
						}
						return nil
					},
				}
				rt, _, cleanup := factory.create(t, addr, &testSTDClientConfig{stdConfig: baseTLS}, &quic.Config{
					ChromeParrot:         true,
					HandshakeIdleTimeout: 5 * time.Second,
				})
				defer cleanup()

				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := rt.RoundTrip(req)
				if err != nil {
					t.Fatalf("RoundTrip failed: %v", err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != 233 {
					t.Fatalf("status = %d, want 233", resp.StatusCode)
				}
				if !verifyCalled.Load() {
					t.Fatal("VerifyConnection was not called")
				}

				hello := readObservedHello(t, helloCh)
				if hello.serverName != "" {
					t.Fatalf("server observed SNI %q, want empty", hello.serverName)
				}
				if slices.Contains(hello.extensions, 0) {
					t.Fatalf("server observed SNI extension (0) when empty SNI requested: %v", hello.extensions)
				}
				if !slices.Contains(hello.extensions, chromeTrustAnchorsExt) {
					t.Fatalf("ChromeParrot extension %#x missing from %v", chromeTrustAnchorsExt, hello.extensions)
				}

				auth := readObservedAuth(t, authCh)
				if auth.host != "hysteria" || auth.path != "/auth" || auth.negotiated != http3.NextProtoH3 {
					t.Fatalf("unexpected HTTP/3 auth request: %+v", auth)
				}
				if baseTLS.ServerName != "" || !slices.Equal(baseTLS.NextProtos, []string{"custom-alpn"}) {
					t.Fatalf("base TLS config mutated: ServerName=%q NextProtos=%v", baseTLS.ServerName, baseTLS.NextProtos)
				}
			})

			t.Run("explicit SNI preserved without mutating base config", func(t *testing.T) {
				addr, helloCh, authCh, _ := startHTTP3AuthServer(t, cert)

				baseTLS := &tls.Config{
					ServerName: "cert.example",
					RootCAs:    roots,
					NextProtos: []string{"custom-alpn"},
				}
				rt, _, cleanup := factory.create(t, addr, &testSTDClientConfig{stdConfig: baseTLS}, &quic.Config{
					ChromeParrot:         true,
					HandshakeIdleTimeout: 5 * time.Second,
				})
				defer cleanup()

				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := rt.RoundTrip(req)
				if err != nil {
					t.Fatalf("RoundTrip failed: %v", err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != 233 {
					t.Fatalf("status = %d, want 233", resp.StatusCode)
				}

				hello := readObservedHello(t, helloCh)
				if hello.serverName != "cert.example" {
					t.Fatalf("server observed SNI %q, want %q", hello.serverName, "cert.example")
				}
				auth := readObservedAuth(t, authCh)
				if auth.host != "hysteria" || auth.negotiated != http3.NextProtoH3 {
					t.Fatalf("unexpected HTTP/3 auth request: %+v", auth)
				}
				if baseTLS.ServerName != "cert.example" || !slices.Equal(baseTLS.NextProtos, []string{"custom-alpn"}) {
					t.Fatalf("base TLS config mutated: ServerName=%q NextProtos=%v", baseTLS.ServerName, baseTLS.NextProtos)
				}
			})

			t.Run("empty SNI rejection aborts before auth", func(t *testing.T) {
				addr, helloCh, _, authCount := startHTTP3AuthServer(t, cert)

				rejectErr := errors.New("verify rejected")
				baseTLS := &tls.Config{
					ServerName:         "",
					InsecureSkipVerify: true,
					VerifyConnection: func(tls.ConnectionState) error {
						return rejectErr
					},
				}
				rt, _, cleanup := factory.create(t, addr, &testSTDClientConfig{stdConfig: baseTLS}, &quic.Config{
					ChromeParrot:         true,
					HandshakeIdleTimeout: 5 * time.Second,
				})
				defer cleanup()

				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := rt.RoundTrip(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if !errors.Is(err, rejectErr) {
					t.Fatalf("RoundTrip error = %v, want %v", err, rejectErr)
				}
				hello := readObservedHello(t, helloCh)
				if hello.serverName != "" || slices.Contains(hello.extensions, 0) {
					t.Fatalf("server observed unexpected SNI %q extensions %v", hello.serverName, hello.extensions)
				}
				if authCount.Load() != 0 {
					t.Fatalf("HTTP/3 auth handler ran %d times despite rejected certificate", authCount.Load())
				}
			})
		})
	}
}
