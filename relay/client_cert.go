package main

import (
	"crypto/sha256"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"sync"
)

// RELAY_CLIENT_CERTS=log (test instances only): the TLS handshake asks the device for a
// client certificate without checking it, and the relay logs what each connection
// presented. Access is still decided by the Authorization header alone. Session
// tickets are off then: a resumed session would report the certificate (or
// none) of the connection that made the ticket.
func clientCertMode() tls.ClientAuthType {
	if os.Getenv("RELAY_CLIENT_CERTS") == "log" {
		return tls.RequestClientCert
	}
	return tls.NoClientCert
}

var clientCertSeen sync.Map

// HTTP/3 requests carry their connection's TLS state; HTTP/2 logs at the handshake
// instead (x/net leaves r.TLS nil for plain CONNECT, which has no :scheme).
func logClientCertRequest(r *http.Request) {
	if r.TLS == nil || r.ProtoMajor != 3 || clientCertMode() == tls.NoClientCert {
		return
	}
	logClientCert("http3", r.RemoteAddr, r.TLS)
}

// One line per connection and certificate.
func logClientCert(transport, remote string, state *tls.ConnectionState) {
	if clientCertMode() == tls.NoClientCert {
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
