// iphonetest: a throwaway ACME server and profile builder for testing, on a real
// iPhone, whether a relay profile can be bound to one device (see README.md).
//
//	iphonetest serve   -state DIR -listen :8464 -base https://relay.example:8464
//	iphonetest profile -state DIR -base https://relay.example:8464 -relay https://relay.example:8463 \
//	                   -bearer 'Bearer name:secret' -variant acme|acme-attest|p12|token -transport both|h2|h3
//
// The server is deliberately permissive and verbose: it logs every request
// (decoded JWS, the device's attestation object, the CSR) to DIR/log.jsonl and
// accepts any challenge answer. The one rule it enforces is the one under test:
// each profile's ClientIdentifier gets one certificate, ever.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: iphonetest serve|profile ...")
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "profile":
		profile(os.Args[2:])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

var b64 = base64.RawURLEncoding

func randomID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return b64.EncodeToString(b)
}

// ---- test CA -------------------------------------------------------------

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func loadCA(state string) (*authority, error) {
	certFile, keyFile := filepath.Join(state, "ca.pem"), filepath.Join(state, "ca.key")
	if _, err := os.Stat(certFile); errors.Is(err, os.ErrNotExist) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:   pkix.Name{CommonName: "Relay device test CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		keyDER, _ := x509.MarshalECPrivateKey(key)
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
			return nil, err
		}
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("bad CA files")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: key, pem: certPEM}, nil
}

func (ca *authority) issue(public any, subject pkix.Name, dns []string, uris []string, days int) ([]byte, *x509.Certificate, error) {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	template := &x509.Certificate{SerialNumber: serial, Subject: subject, DNSNames: dns,
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(0, 0, days),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return der, cert, err
}

// ---- one-time enrolment tokens (ClientIdentifier) --------------------------

type grant struct {
	Variant  string `json:"variant"`
	Created  int64  `json:"created"`
	UsedAt   int64  `json:"used_at,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Profile  string `json:"profile"`
	Attempts int    `json:"refused_attempts,omitempty"`
}

var grantsMu sync.Mutex

func readGrants(state string) map[string]*grant {
	out := map[string]*grant{}
	if b, err := os.ReadFile(filepath.Join(state, "grants.json")); err == nil {
		json.Unmarshal(b, &out)
	}
	return out
}

func writeGrants(state string, grants map[string]*grant) error {
	b, _ := json.MarshalIndent(grants, "", "  ")
	tmp := filepath.Join(state, "grants.json.tmp")
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(state, "grants.json"))
}

// ---- ACME server -----------------------------------------------------------

type acmeServer struct {
	state, base string
	ca          *authority
	mu          sync.Mutex
	nonces      map[string]bool
	accounts    map[string]map[string]any // kid -> jwk
	orders      map[string]*order
	authzs      map[string]*order // authz id -> its order (one identifier per order)
	logMu       sync.Mutex
	logFile     *os.File
}

type order struct {
	id, authz, challenge, token, account string
	identifiers                          []map[string]any
	identifier                           string
	status, authzStatus                  string
	cert                                 []byte
	expires                              time.Time
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	state := fs.String("state", "/state", "state directory")
	listen := fs.String("listen", ":8464", "HTTPS listen address")
	base := fs.String("base", "", "public origin, e.g. https://relay.example.com:8464")
	certFile := fs.String("cert", "/tls/fullchain.pem", "TLS certificate chain")
	keyFile := fs.String("key", "/tls/privkey.pem", "TLS key")
	plain := fs.Bool("plain-http", false, "serve plain HTTP (local tests only)")
	fs.Parse(args)
	if *base == "" {
		log.Fatal("-base is required")
	}
	os.MkdirAll(filepath.Join(*state, "profiles"), 0700)
	ca, err := loadCA(*state)
	if err != nil {
		log.Fatal(err)
	}
	logFile, err := os.OpenFile(filepath.Join(*state, "log.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	s := &acmeServer{state: *state, base: strings.TrimRight(*base, "/"), ca: ca, nonces: map[string]bool{},
		accounts: map[string]map[string]any{}, orders: map[string]*order{}, authzs: map[string]*order{}, logFile: logFile}
	server := &http.Server{Addr: *listen, Handler: s, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("ACME test server on %s, directory %s/acme/directory", *listen, s.base)
	if *plain {
		log.Fatal(server.ListenAndServe())
	}
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))
}

func (s *acmeServer) record(entry map[string]any) {
	entry["ts"] = time.Now().Format(time.RFC3339Nano)
	b, _ := json.Marshal(entry)
	s.logMu.Lock()
	s.logFile.Write(append(b, '\n'))
	s.logMu.Unlock()
	short := string(b)
	if len(short) > 600 {
		short = short[:600] + "…"
	}
	log.Print(short)
}

func (s *acmeServer) nonce() string {
	n := randomID(16)
	s.mu.Lock()
	s.nonces[n] = true
	s.mu.Unlock()
	return n
}

func (s *acmeServer) reply(w http.ResponseWriter, status int, body any, entry map[string]any) {
	w.Header().Set("Replay-Nonce", s.nonce())
	w.Header().Set("Link", "<"+s.base+"/acme/directory>;rel=\"index\"")
	w.Header().Set("Cache-Control", "no-store")
	entry["status"] = status
	switch v := body.(type) {
	case []byte:
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(status)
		w.Write(v)
	default:
		if status >= 400 {
			w.Header().Set("Content-Type", "application/problem+json")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
		entry["response"] = body
	}
	s.record(entry)
}

func problem(kind, detail string) map[string]any {
	return map[string]any{"type": "urn:ietf:params:acme:error:" + kind, "detail": detail}
}

func (s *acmeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	entry := map[string]any{"method": r.Method, "path": r.URL.Path, "remote": r.RemoteAddr,
		"user_agent": r.UserAgent(), "proto": r.Proto}
	if r.TLS != nil {
		entry["tls"] = fmt.Sprintf("%x", r.TLS.Version)
	}
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/p/") && strings.HasSuffix(path, ".mobileconfig") && r.Method == http.MethodGet:
		name := filepath.Base(path)
		data, err := os.ReadFile(filepath.Join(s.state, "profiles", name))
		if err != nil {
			http.NotFound(w, r)
			entry["status"] = 404
			s.record(entry)
			return
		}
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
		entry["status"] = 200
		s.record(entry)
		return
	case path == "/acme/directory":
		s.reply(w, 200, map[string]any{
			"newNonce": s.base + "/acme/new-nonce", "newAccount": s.base + "/acme/new-account",
			"newOrder": s.base + "/acme/new-order", "revokeCert": s.base + "/acme/revoke-cert",
			"keyChange": s.base + "/acme/key-change", "meta": map[string]any{"externalAccountRequired": false}}, entry)
		return
	case path == "/acme/new-nonce":
		w.Header().Set("Replay-Nonce", s.nonce())
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(204)
		}
		entry["status"] = "nonce"
		s.record(entry)
		return
	}
	if r.Method != http.MethodPost {
		s.reply(w, 405, problem("malformed", "POST required"), entry)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	entry["content_type"] = r.Header.Get("Content-Type")
	protected, payload, kid, jwk, err := s.verify(body, r, entry)
	if err != nil {
		s.reply(w, 400, problem("malformed", err.Error()), entry)
		return
	}
	_ = protected
	switch {
	case path == "/acme/new-account":
		thumb := thumbprint(jwk)
		id := s.base + "/acme/acct/" + thumb[:16]
		s.mu.Lock()
		s.accounts[id] = jwk
		s.mu.Unlock()
		w.Header().Set("Location", id)
		s.reply(w, 201, map[string]any{"status": "valid", "orders": id + "/orders"}, entry)
	case path == "/acme/new-order":
		s.newOrder(w, payload, kid, entry)
	case strings.HasPrefix(path, "/acme/order/") && strings.HasSuffix(path, "/finalize"):
		s.finalize(w, strings.TrimSuffix(strings.TrimPrefix(path, "/acme/order/"), "/finalize"), payload, entry)
	case strings.HasPrefix(path, "/acme/order/"):
		s.mu.Lock()
		o := s.orders[strings.TrimPrefix(path, "/acme/order/")]
		s.mu.Unlock()
		if o == nil {
			s.reply(w, 404, problem("malformed", "no such order"), entry)
			return
		}
		s.reply(w, 200, s.orderJSON(o), entry)
	case strings.HasPrefix(path, "/acme/authz/"):
		s.mu.Lock()
		o := s.authzs[strings.TrimPrefix(path, "/acme/authz/")]
		s.mu.Unlock()
		if o == nil {
			s.reply(w, 404, problem("malformed", "no such authorization"), entry)
			return
		}
		s.reply(w, 200, s.authzJSON(o), entry)
	case strings.HasPrefix(path, "/acme/chall/"):
		s.challenge(w, strings.TrimPrefix(path, "/acme/chall/"), payload, entry)
	case strings.HasPrefix(path, "/acme/cert/"):
		var chain []byte
		s.mu.Lock()
		if o := s.orders[strings.TrimPrefix(path, "/acme/cert/")]; o != nil {
			chain = o.cert
		}
		s.mu.Unlock()
		if chain == nil {
			s.reply(w, 404, problem("malformed", "no such certificate"), entry)
			return
		}
		s.reply(w, 200, chain, entry)
	default:
		s.reply(w, 404, problem("malformed", "unknown resource"), entry)
	}
}

// verify decodes a flattened JWS and checks its signature. Failures are logged,
// not refused (this server exists to observe what the device sends), except
// for bodies that cannot be decoded at all.
func (s *acmeServer) verify(body []byte, r *http.Request, entry map[string]any) (map[string]any, []byte, string, map[string]any, error) {
	var jws struct{ Protected, Payload, Signature string }
	if err := json.Unmarshal(body, &jws); err != nil {
		entry["raw_body"] = string(body)
		return nil, nil, "", nil, fmt.Errorf("not a JWS: %v", err)
	}
	protectedRaw, err1 := b64.DecodeString(jws.Protected)
	payload, err2 := b64.DecodeString(jws.Payload)
	signature, err3 := b64.DecodeString(jws.Signature)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, nil, "", nil, err
	}
	var protected map[string]any
	if err := json.Unmarshal(protectedRaw, &protected); err != nil {
		return nil, nil, "", nil, err
	}
	entry["jws_protected"] = protected
	if len(payload) == 0 {
		entry["jws_payload"] = "(POST-as-GET)"
	} else {
		var decoded any
		if json.Unmarshal(payload, &decoded) == nil {
			entry["jws_payload"] = decoded
		} else {
			entry["jws_payload_raw"] = string(payload)
		}
	}
	nonce, _ := protected["nonce"].(string)
	s.mu.Lock()
	entry["nonce_ok"] = s.nonces[nonce]
	delete(s.nonces, nonce)
	s.mu.Unlock()
	entry["url_ok"] = protected["url"] == s.base+r.URL.Path
	kid, _ := protected["kid"].(string)
	jwk, _ := protected["jwk"].(map[string]any)
	if jwk == nil && kid != "" {
		s.mu.Lock()
		jwk = s.accounts[kid]
		s.mu.Unlock()
	}
	alg, _ := protected["alg"].(string)
	if jwk == nil {
		entry["signature"] = "no key"
	} else if err := checkSignature(alg, jwk, []byte(jws.Protected+"."+jws.Payload), signature); err != nil {
		entry["signature"] = "BAD: " + err.Error()
	} else {
		entry["signature"] = "ok"
	}
	return protected, payload, kid, jwk, nil
}

func checkSignature(alg string, jwk map[string]any, signed, signature []byte) error {
	field := func(k string) []byte { v, _ := jwk[k].(string); b, _ := b64.DecodeString(v); return b }
	switch alg {
	case "ES256", "ES384":
		curve, hash, size := elliptic.P256(), crypto.SHA256, 32
		if alg == "ES384" {
			curve, hash, size = elliptic.P384(), crypto.SHA384, 48
		}
		if len(signature) != 2*size {
			return fmt.Errorf("signature length %d", len(signature))
		}
		key := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(field("x")), Y: new(big.Int).SetBytes(field("y"))}
		var digest []byte
		if hash == crypto.SHA256 {
			d := sha256.Sum256(signed)
			digest = d[:]
		} else {
			d := sha512.Sum384(signed)
			digest = d[:]
		}
		if !ecdsa.Verify(key, digest, new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:])) {
			return errors.New("ecdsa mismatch")
		}
		return nil
	case "RS256":
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(field("n")), E: int(new(big.Int).SetBytes(field("e")).Int64())}
		d := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, d[:], signature)
	}
	return fmt.Errorf("unsupported alg %q", alg)
}

// thumbprint: RFC 7638 for EC and RSA keys.
func thumbprint(jwk map[string]any) string {
	var canonical string
	if jwk["kty"] == "RSA" {
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk["e"], jwk["n"])
	} else {
		canonical = fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	}
	d := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(d[:])
}

func (s *acmeServer) newOrder(w http.ResponseWriter, payload []byte, kid string, entry map[string]any) {
	var request struct {
		Identifiers []map[string]any `json:"identifiers"`
	}
	json.Unmarshal(payload, &request)
	// Only a spent identifier is refused: anything unexpected (no identifier, several,
	// one this server never issued) is logged and let through, to see the rest of the flow.
	if len(request.Identifiers) != 1 {
		entry["unexpected"] = fmt.Sprintf("%d identifiers", len(request.Identifiers))
	}
	if len(request.Identifiers) == 0 {
		request.Identifiers = []map[string]any{{"type": "none", "value": ""}}
	}
	value, _ := request.Identifiers[0]["value"].(string)
	grantsMu.Lock()
	grants := readGrants(s.state)
	g := grants[value]
	refused := ""
	if g == nil {
		entry["unexpected_identifier"] = "not issued by this server: " + value
	} else if g.UsedAt != 0 {
		refused = fmt.Sprintf("ClientIdentifier already used at %s (certificate %s)", time.Unix(g.UsedAt, 0).Format(time.RFC3339), g.Serial)
		g.Attempts++
		writeGrants(s.state, grants)
	}
	grantsMu.Unlock()
	if refused != "" {
		entry["refused"] = refused
		s.reply(w, 403, problem("rejectedIdentifier", refused), entry)
		return
	}
	o := &order{id: randomID(12), authz: randomID(12), challenge: randomID(12), token: randomID(32), account: kid,
		identifiers: request.Identifiers, identifier: value, status: "pending", authzStatus: "pending",
		expires: time.Now().Add(time.Hour)}
	s.mu.Lock()
	s.orders[o.id] = o
	s.authzs[o.authz] = o
	s.mu.Unlock()
	w.Header().Set("Location", s.base+"/acme/order/"+o.id)
	s.reply(w, 201, s.orderJSON(o), entry)
}

// orderJSON and authzJSON take s.mu themselves: the challenge and finalize
// handlers change the order while other requests read it.
func (s *acmeServer) orderJSON(o *order) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{"status": o.status, "expires": o.expires.UTC().Format(time.RFC3339),
		"identifiers": o.identifiers, "authorizations": []string{s.base + "/acme/authz/" + o.authz},
		"finalize": s.base + "/acme/order/" + o.id + "/finalize"}
	if o.cert != nil {
		out["certificate"] = s.base + "/acme/cert/" + o.id
	}
	return out
}

func (s *acmeServer) authzJSON(o *order) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{"status": o.authzStatus, "expires": o.expires.UTC().Format(time.RFC3339),
		"identifier": o.identifiers[0],
		"challenges": []map[string]any{{"type": "device-attest-01", "url": s.base + "/acme/chall/" + o.challenge,
			"status": o.authzStatus, "token": o.token}}}
}

func (s *acmeServer) challenge(w http.ResponseWriter, id string, payload []byte, entry map[string]any) {
	s.mu.Lock()
	var o *order
	for _, candidate := range s.orders {
		if candidate.challenge == id {
			o = candidate
		}
	}
	s.mu.Unlock()
	if o == nil {
		s.reply(w, 404, problem("malformed", "no such challenge"), entry)
		return
	}
	var answer map[string]any
	json.Unmarshal(payload, &answer)
	if att, ok := answer["attObj"].(string); ok {
		raw, err := b64.DecodeString(strings.TrimRight(att, "="))
		if err != nil {
			raw, _ = base64.StdEncoding.DecodeString(att)
		}
		os.WriteFile(filepath.Join(s.state, "attobj-"+o.id+".cbor"), raw, 0600)
		entry["attestation"] = describeAttestation(raw)
	}
	// Permissive: any answer (empty, none, apple) validates the authorization.
	s.mu.Lock()
	o.authzStatus, o.status = "valid", "ready"
	s.mu.Unlock()
	w.Header().Set("Link", "<"+s.base+"/acme/authz/"+o.authz+">;rel=\"up\"")
	s.reply(w, 200, map[string]any{"type": "device-attest-01", "url": s.base + "/acme/chall/" + o.challenge,
		"status": "valid", "token": o.token, "validated": time.Now().UTC().Format(time.RFC3339)}, entry)
}

func describeAttestation(raw []byte) map[string]any {
	out := map[string]any{"bytes": len(raw)}
	v, err := decodeCBOR(raw)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	m, _ := v.(map[string]any)
	out["fmt"] = m["fmt"]
	if authData, ok := m["authData"].([]byte); ok {
		out["authData_len"] = len(authData)
	}
	stmt, _ := m["attStmt"].(map[string]any)
	keys := []string{}
	for k := range stmt {
		keys = append(keys, k)
	}
	out["attStmt_keys"] = keys
	if chain, ok := stmt["x5c"].([]any); ok {
		certs := []map[string]any{}
		for _, item := range chain {
			der, _ := item.([]byte)
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				certs = append(certs, map[string]any{"error": err.Error()})
				continue
			}
			c := map[string]any{"subject": cert.Subject.String(), "issuer": cert.Issuer.String(),
				"not_after": cert.NotAfter.Format(time.RFC3339)}
			apple := map[string]string{}
			for _, ext := range cert.Extensions {
				if strings.HasPrefix(ext.Id.String(), "1.2.840.113635.") {
					apple[ext.Id.String()] = printable(ext.Value)
				}
			}
			c["apple_extensions"] = apple
			certs = append(certs, c)
		}
		out["x5c"] = certs
	}
	return out
}

// printable shows an extension value as text when it is (wrapped) text, else hex.
func printable(value []byte) string {
	var s string
	if _, err := asn1.Unmarshal(value, &s); err == nil {
		return s
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(value, &raw); err == nil && len(raw.Bytes) > 0 {
		if strings.IndexFunc(string(raw.Bytes), func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
			return string(raw.Bytes)
		}
	}
	return hex.EncodeToString(value)
}

func (s *acmeServer) finalize(w http.ResponseWriter, id string, payload []byte, entry map[string]any) {
	s.mu.Lock()
	o := s.orders[id]
	s.mu.Unlock()
	if o == nil {
		s.reply(w, 404, problem("malformed", "no such order"), entry)
		return
	}
	var request struct {
		CSR string `json:"csr"`
	}
	json.Unmarshal(payload, &request)
	der, err := b64.DecodeString(strings.TrimRight(request.CSR, "="))
	if err != nil {
		der, err = base64.StdEncoding.DecodeString(request.CSR)
	}
	if err != nil {
		s.reply(w, 400, problem("badCSR", "CSR is not base64url"), entry)
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		s.reply(w, 400, problem("badCSR", err.Error()), entry)
		return
	}
	info := map[string]any{"subject": csr.Subject.String(), "dns": csr.DNSNames, "emails": csr.EmailAddresses,
		"signature_ok": csr.CheckSignature() == nil, "key": fmt.Sprintf("%T", csr.PublicKey)}
	if k, ok := csr.PublicKey.(*ecdsa.PublicKey); ok {
		info["curve"] = k.Curve.Params().Name
	}
	uris := []string{}
	for _, u := range csr.URIs {
		uris = append(uris, u.String())
	}
	info["uris"] = uris
	exts := []string{}
	for _, e := range csr.Extensions {
		exts = append(exts, e.Id.String())
	}
	info["extensions"] = exts
	entry["csr"] = info
	// The one-time rule: the identifier is spent when its certificate is issued.
	grantsMu.Lock()
	grants := readGrants(s.state)
	g := grants[o.identifier]
	if g == nil { // an identifier this server never issued: spent from now on as well
		g = &grant{Variant: "unexpected", Created: time.Now().Unix()}
		grants[o.identifier] = g
	}
	if g.UsedAt != 0 {
		grantsMu.Unlock()
		s.reply(w, 403, problem("rejectedIdentifier", "ClientIdentifier already used"), entry)
		return
	}
	subject := csr.Subject
	if subject.CommonName == "" {
		subject.CommonName = "device-" + o.identifier[:min(8, len(o.identifier))]
	}
	certDER, cert, err := s.ca.issue(csr.PublicKey, subject, csr.DNSNames, nil, 30)
	if err != nil {
		grantsMu.Unlock()
		s.reply(w, 500, problem("serverInternal", err.Error()), entry)
		return
	}
	g.UsedAt, g.Serial = time.Now().Unix(), cert.SerialNumber.Text(16)
	writeGrants(s.state, grants)
	grantsMu.Unlock()
	entry["issued_serial"] = g.Serial
	var chain bytes.Buffer
	pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	chain.Write(s.ca.pem)
	s.mu.Lock()
	o.cert, o.status = chain.Bytes(), "valid"
	s.mu.Unlock()
	w.Header().Set("Location", s.base+"/acme/order/"+o.id)
	s.reply(w, 200, s.orderJSON(o), entry)
}
