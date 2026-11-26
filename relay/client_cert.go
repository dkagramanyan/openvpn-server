package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"sync"
)

// The relay asks every direct TLS connection for a client certificate and never
// checks it in the handshake: a device-bound profile presents the identity the
// phone made over ACME, an older profile presents none. TLS still proves that the
// device holds the key (CertificateVerify); which certificate belongs to which
// device is the policy service's decision (X-Relay-Device).
//
// RELAY_CLIENT_CERTS: "request" (the default), "off" (never ask), or "log" (ask,
// and log what each connection presented, with session tickets off so that a
// resumed session cannot repeat an earlier connection's line; test instances).
func clientCertMode() tls.ClientAuthType {
	if os.Getenv("RELAY_CLIENT_CERTS") == "off" {
		return tls.NoClientCert
	}
	return tls.RequestClientCert
}

func clientCertLogging() bool { return os.Getenv("RELAY_CLIENT_CERTS") == "log" }

// deviceID is the SHA-256 (hex) of the connection's client certificate, or "".
func deviceID(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:])
}

type deviceKey struct{}

// HTTP/2 over the relay's own TLS: x/net leaves r.TLS nil for plain CONNECT
// (no :scheme), so the connection's device rides in the request context.
func withConnectionDevice(ctx context.Context, state *tls.ConnectionState) context.Context {
	return context.WithValue(ctx, deviceKey{}, deviceID(state))
}

// requestDevice: the device of the TLS connection a request arrived on, from the
// handshake only, never from a header. Behind the trusted proxy there is none.
func requestDevice(r *http.Request) string {
	if device, ok := r.Context().Value(deviceKey{}).(string); ok {
		return device
	}
	if r.TLS != nil {
		return deviceID(r.TLS)
	}
	return ""
}

// withDevice: the credential the policy service checks, the header plus the device.
func withDevice(token, device string) string {
	if device == "" {
		return token
	}
	return token + "\x00" + device
}

var clientCertSeen sync.Map

// HTTP/3 requests carry their connection's TLS state; HTTP/2 logs at the handshake.
func logClientCertRequest(r *http.Request) {
	if r.TLS == nil || r.ProtoMajor != 3 || !clientCertLogging() {
		return
	}
	logClientCert("http3", r.RemoteAddr, r.TLS)
}

// One line per connection and certificate.
func logClientCert(transport, remote string, state *tls.ConnectionState) {
	if !clientCertLogging() {
		return
	}
	var subject, issuer, serial string
	var fingerprint [32]byte
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		subject, issuer, serial = leaf.Subject.String(), leaf.Issuer.String(), leaf.SerialNumber.Text(16)
		fingerprint = sha256.Sum256(leaf.Raw)
	}
	key := transport + "|" + remote
	if previous, loaded := clientCertSeen.Swap(key, fingerprint); loaded && previous == fingerprint {
		return
	}
	log.Printf("client-cert transport=%s remote=%s tls=%x resumed=%t present=%t chain=%d subject=%q issuer=%q serial=%s sha256=%x",
		transport, remote, state.Version, state.DidResume, len(state.PeerCertificates) > 0, len(state.PeerCertificates),
		subject, issuer, serial, fingerprint)
}
