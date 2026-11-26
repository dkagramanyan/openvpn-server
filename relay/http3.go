package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// certificateFiles serves the relay hostname's certificate from two PEM files
// and picks up a renewed pair without a restart. A pair that fails to load
// (for example while it is being replaced) keeps the previous one in use.
// tlsConfig serves the relay's certificate for the given ALPN protocols.
func (c *certificateFiles) tlsConfig(protocols ...string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: protocols, ClientAuth: clientCertMode(),
		SessionTicketsDisabled: clientCertMode() != tls.NoClientCert,
		GetCertificate:         func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return c.get() }}
}

// details of the certificate in use, for the status page: names, expiry, issuer.
func (c *certificateFiles) details() map[string]any {
	pair, err := c.get()
	if err != nil || pair == nil || len(pair.Certificate) == 0 {
		return nil
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil
		}
	}
	return map[string]any{"names": leaf.DNSNames, "not_after": leaf.NotAfter.Unix(), "issuer": leaf.Issuer.CommonName,
		"ok": time.Now().Before(leaf.NotAfter)}
}

type certificateFiles struct {
	chain, key string
	mu         sync.Mutex
	loaded     *tls.Certificate
	stamp      [2]time.Time
	checked    time.Time
}

func (c *certificateFiles) get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded != nil && time.Since(c.checked) < 30*time.Second {
		return c.loaded, nil
	}
	c.checked = time.Now()
	var stamp [2]time.Time
	for i, path := range []string{c.chain, c.key} {
		info, err := os.Stat(path)
		if err != nil {
			if c.loaded != nil {
				return c.loaded, nil
			}
			return nil, err
		}
		stamp[i] = info.ModTime()
	}
	if c.loaded != nil && stamp == c.stamp {
		return c.loaded, nil
	}
	pair, err := tls.LoadX509KeyPair(c.chain, c.key)
	if err != nil {
		if c.loaded != nil {
			return c.loaded, nil
		}
		return nil, err
	}
	if c.loaded != nil {
		log.Print("Relay certificate reloaded")
	}
	c.loaded, c.stamp = &pair, stamp
	return c.loaded, nil
}

// resetKey is derived from the private key file, so it is the same after a
// restart: connections the previous process held are reset too.
func (c *certificateFiles) resetKey() *quic.StatelessResetKey {
	data, err := os.ReadFile(c.key)
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, data)
	mac.Write([]byte("apple-relay stateless reset"))
	return (*quic.StatelessResetKey)(mac.Sum(nil))
}

// One phone keeps one QUIC connection for all of its flows, so the stream
// limit is the per-client flow limit, and the windows let a single download
// or upload use a fast path fully.
func (s *relayServer) http3Server(certificate func() (*tls.Certificate, error)) *http3.Server {
	streams := int64(256)
	if s.quota != nil && s.quota.maximum > 0 {
		streams = int64(s.quota.maximum)
	}
	return &http3.Server{Handler: s, EnableDatagrams: true, MaxHeaderBytes: 8192,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: clientCertMode(),
			SessionTicketsDisabled: clientCertMode() != tls.NoClientCert,
			GetCertificate:         func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate() }}),
		QUICConfig: &quic.Config{KeepAlivePeriod: 20 * time.Second, MaxIdleTimeout: 90 * time.Second,
			MaxIncomingStreams:         streams,
			InitialStreamReceiveWindow: 1 << 20, MaxStreamReceiveWindow: 8 << 20,
			InitialConnectionReceiveWindow: 2 << 20, MaxConnectionReceiveWindow: 32 << 20}}
}

// serveHTTP3 runs until the context ends. Without a certificate it waits for
// one, so HTTP/2 keeps serving and HTTP/3 starts once the files are in place.
func (s *relayServer) serveHTTP3(ctx context.Context, address string, files *certificateFiles, up func(bool)) error {
	for notified := false; ; {
		if _, err := files.get(); err == nil {
			break
		} else if !notified {
			log.Printf("HTTP/3 is waiting for %s and %s (readable by UID 65532): %v", files.chain, files.key, err)
			notified = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	defer udp.Close()
	server := s.http3Server(files.get)
	// A phone that wakes with a connection this relay has dropped (idle for 90 s,
	// or the relay restarted) must be told at once: without a reset key quic-go
	// ignores its packets and the phone waits out its own timeout.
	transport := &quic.Transport{Conn: udp, StatelessResetKey: files.resetKey()}
	defer transport.Close()
	config := server.QUICConfig.Clone()
	config.EnableDatagrams = true
	listener, err := transport.ListenEarly(server.TLSConfig, config)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); server.Close() }()
	up(true)
	defer up(false)
	log.Printf("Apple Network Relay HTTP/3 listening on %s/udp", udp.LocalAddr())
	err = server.ServeListener(listener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

const udpIdle = 2 * time.Minute

// HTTP/3 carries CONNECT-UDP payloads as QUIC datagrams with context ID 0
// (RFC 9298). Both directions are counted, like on HTTP/2.
func (s *relayServer) proxyHTTP3UDP(ctx context.Context, w http.ResponseWriter, conn *net.UDPConn,
	token string, addr netip.Addr, origin string) {
	flow := flowFrom(ctx)
	// Before HTTPStream: taking the stream sends the response headers.
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)
	stream := w.(http3.HTTPStreamer).HTTPStream()
	var once sync.Once
	closeFlow := func() {
		once.Do(func() {
			conn.Close()
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
			stream.Close()
		})
	}
	defer closeFlow()
	go s.watch(ctx, token, addr, origin, closeFlow)
	_ = conn.SetReadBuffer(1 << 20) // a download burst, as on HTTP/2
	_ = conn.SetReadDeadline(time.Now().Add(udpIdle))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // client -> destination
		defer wg.Done()
		defer closeFlow()
		for {
			data, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			contextID, n, err := quicvarint.Parse(data)
			if err != nil {
				return
			}
			if contextID != 0 || len(data)-n > maxUDPPayload {
				continue
			}
			sent, err := conn.Write(data[n:])
			flow.add(int64(sent), 0)
			if err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(udpIdle))
		}
	}()
	go func() { // destination -> client
		defer wg.Done()
		defer closeFlow()
		buffer := make([]byte, 1+maxUDPPayload+1) // buffer[0] = context ID 0
		for {
			n, err := conn.Read(buffer[1:])
			if err != nil {
				return
			}
			if n > maxUDPPayload {
				continue
			}
			if err := stream.SendDatagram(buffer[:n+1]); err != nil {
				// A datagram above the path's size is lost, as on any UDP path.
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					s.metrics.observe("udp_oversize_drops", time.Time{})
					continue
				}
				return
			}
			flow.add(0, int64(n))
			_ = conn.SetReadDeadline(time.Now().Add(udpIdle))
		}
	}()
	// The request stream carries only capsules we do not use; its end is the
	// client closing the flow.
	_, _ = io.Copy(io.Discard, stream)
	closeFlow()
	wg.Wait()
}
