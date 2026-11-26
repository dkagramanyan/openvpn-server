package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"html"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// One top-level identifier for every test profile: installing the next variant
// replaces the previous one, so the phone never has two test relays at once.
const profileIdentifier = "org.openvpn.relay-device-test"

const udpTemplate = "/.well-known/masque/udp/{target_host}/{target_port}/"

func uuid4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

func profile(args []string) {
	fs := flag.NewFlagSet("profile", flag.ExitOnError)
	state := fs.String("state", "/state", "state directory (shared with serve)")
	base := fs.String("base", "", "ACME/profile server origin, e.g. https://relay.example.com:8464")
	relay := fs.String("relay", "", "test relay origin, e.g. https://relay.example.com:8463")
	bearer := fs.String("bearer", "", "the relay credential, 'Bearer name:secret'")
	variant := fs.String("variant", "acme", "acme | acme-attest | p12 | token")
	transport := fs.String("transport", "both", "both | h2 | h3")
	fs.Parse(args)
	if *base == "" || *relay == "" || !strings.HasPrefix(*bearer, "Bearer ") {
		log.Fatal("-base, -relay and -bearer 'Bearer name:secret' are required")
	}
	*base, *relay = strings.TrimRight(*base, "/"), strings.TrimRight(*relay, "/")
	os.MkdirAll(filepath.Join(*state, "profiles"), 0700)
	tag := randomID(6)
	title := fmt.Sprintf("Relay device test · %s · %s · %s", *variant, *transport, tag)

	payload := func(kind, suffix, uuid string) dict {
		return dict{"PayloadType": kind, "PayloadVersion": 1, "PayloadIdentifier": profileIdentifier + suffix,
			"PayloadUUID": uuid, "PayloadDisplayName": title}
	}
	relayEntry := dict{"AdditionalHTTPHeaderFields": dict{"Authorization": *bearer}}
	switch *transport {
	case "both":
		relayEntry["HTTP3RelayURL"], relayEntry["HTTP2RelayURL"] = *relay+udpTemplate, *relay+udpTemplate
	case "h2":
		relayEntry["HTTP2RelayURL"] = *relay + udpTemplate
	case "h3":
		relayEntry["HTTP3RelayURL"] = *relay + udpTemplate
	default:
		log.Fatalf("unknown transport %q", *transport)
	}
	var content []any
	identityUUID := uuid4()
	switch *variant {
	case "acme", "acme-attest":
		clientID := randomID(24)
		acme := payload("com.apple.security.acme", ".acme", identityUUID)
		acme.merge(dict{"DirectoryURL": *base + "/acme/directory", "ClientIdentifier": clientID,
			"KeyType": "ECSECPrimeRandom", "KeySize": 256, "HardwareBound": true, "Attest": *variant == "acme-attest",
			"Subject":          []any{[]any{[]any{"CN", "relay-device-" + tag}}},
			"ExtendedKeyUsage": []any{"1.3.6.1.5.5.7.3.2"}, "UsageFlags": 1})
		content = append(content, acme)
		grantsMu.Lock()
		grants := readGrants(*state)
		grants[clientID] = &grant{Variant: *variant, Created: time.Now().Unix(), Profile: tag}
		if err := writeGrants(*state, grants); err != nil {
			log.Fatal(err)
		}
		grantsMu.Unlock()
		relayEntry["PayloadCertificateUUID"] = identityUUID
	case "p12":
		p12, err := softwareIdentity(*state, "relay-p12-"+tag)
		if err != nil {
			log.Fatal(err)
		}
		identity := payload("com.apple.security.pkcs12", ".p12", identityUUID)
		identity.merge(dict{"PayloadContent": p12, "Password": "relaytest", "PayloadCertificateFileName": "relay-test.p12"})
		content = append(content, identity)
		relayEntry["PayloadCertificateUUID"] = identityUUID
	case "token":
	default:
		log.Fatalf("unknown variant %q", *variant)
	}
	relayPayload := payload("com.apple.relay.managed", ".relay", uuid4())
	relayPayload.merge(dict{"Relays": []any{relayEntry}, "MatchDomains": []any{}})
	content = append(content, relayPayload)
	top := payload("Configuration", "", uuid4())
	top.merge(dict{"PayloadContent": content, "PayloadDescription": "Test profile: binds the relay to this device."})
	name := randomID(18) + ".mobileconfig"
	if err := os.WriteFile(filepath.Join(*state, "profiles", name), []byte(plist(top)), 0600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n  open in Safari on the iPhone: %s/p/%s\n", title, *base, name)
}

// softwareIdentity: a key made here, packed as PKCS#12 (control case: a copyable identity).
func softwareIdentity(state, cn string) ([]byte, error) {
	ca, err := loadCA(state)
	if err != nil {
		return nil, err
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _, err := ca.issue(&key.PublicKey, pkix.Name{CommonName: cn}, nil, nil, 30)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "p12")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(filepath.Join(dir, "ca.pem"), ca.pem, 0600)
	// SHA1/3DES: the PKCS#12 encryption every iOS version reads.
	out, err := exec.Command("openssl", "pkcs12", "-export", "-inkey", filepath.Join(dir, "key.pem"),
		"-in", filepath.Join(dir, "cert.pem"), "-certfile", filepath.Join(dir, "ca.pem"), "-name", cn,
		"-passout", "pass:relaytest", "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1").Output()
	if err != nil {
		return nil, fmt.Errorf("openssl pkcs12: %v", err)
	}
	return out, nil
}

// ---- a small XML property list writer --------------------------------------

type dict map[string]any

func (d dict) merge(other dict) {
	for k, v := range other {
		d[k] = v
	}
}

func plist(root dict) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n" +
		`<plist version="1.0">` + "\n")
	writeValue(&b, root, 0)
	b.WriteString("</plist>\n")
	return b.String()
}

func writeValue(b *strings.Builder, v any, depth int) {
	pad := strings.Repeat("\t", depth)
	switch x := v.(type) {
	case dict:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString(pad + "<dict>\n")
		for _, k := range keys {
			b.WriteString(pad + "\t<key>" + html.EscapeString(k) + "</key>\n")
			writeValue(b, x[k], depth+1)
		}
		b.WriteString(pad + "</dict>\n")
	case []any:
		b.WriteString(pad + "<array>\n")
		for _, item := range x {
			writeValue(b, item, depth+1)
		}
		b.WriteString(pad + "</array>\n")
	case string:
		b.WriteString(pad + "<string>" + html.EscapeString(x) + "</string>\n")
	case int:
		fmt.Fprintf(b, "%s<integer>%d</integer>\n", pad, x)
	case bool:
		if x {
			b.WriteString(pad + "<true/>\n")
		} else {
			b.WriteString(pad + "<false/>\n")
		}
	case []byte:
		b.WriteString(pad + "<data>" + base64.StdEncoding.EncodeToString(x) + "</data>\n")
	default:
		panic(fmt.Sprintf("plist: unsupported %T", v))
	}
}
