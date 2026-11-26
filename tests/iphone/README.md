# iPhone test: one relay profile, one iPhone

Today an Apple relay profile carries a bearer token, so a copy of the file works
on any number of phones. The idea under test: the profile asks the phone to make
its own key in the Secure Enclave and fetch a certificate for it over ACME (the
`com.apple.security.acme` payload, `HardwareBound: true`), and the relay payload
logs in with that certificate (`PayloadCertificateUUID`). The ACME server gives
each profile one certificate, so a second phone installing a copy is refused.

Nothing in Apple's documentation says whether this works on a profile installed
by hand (without MDM), what the phone sends when `Attest` is false, or whether
iOS presents the certificate over HTTP/3. This test answers those questions.

## What runs

`run.sh up` starts two containers next to the service, without touching it:

| container | port | what it does |
|---|---|---|
| `relay-device-test` | 8463 tcp+udp | a second copy of the relay (same credentials, same policy) that asks every connection for a client certificate and logs what came back. Access is still decided by the token, so nothing is refused because of a certificate. |
| `relay-device-acme` | 8464 tcp | a throwaway ACME server with its own test CA. It logs every request (the phone's attestation, the CSR) and serves the test profiles at `/p/...`. Its one rule: one certificate per profile. |

Both use the relay's Let's Encrypt certificate from `relay-tls/`, and the host name
of the relay URL saved in Settings → Apple relay (override: `RELAY_TEST_HOST=...`).

## Steps

On the MikroTik: forward **8463 tcp + udp** and **8464 tcp** to the macbook (like 8443).

On the macbook:

```sh
git pull
tests/iphone/run.sh up
# a full-access test client (create it in the UI first, and download its Apple relay
# profile once so it has a relay credential), e.g. iphone-test:
tests/iphone/run.sh profile iphone-test token     # 0. control: today's profile on port 8463
```

On the iPhone: switch Wi-Fi off and use **mobile data** for the whole test, remove
the normal relay profile and switch OpenVPN off (two relays at once make the logs
ambiguous, and Wi-Fi at home would reach the server's public name in a loop).
Before each step, **remove the previous test profile** (Settings → General → VPN &
Device Management), so the next one is not downloaded and enrolled through the old
test relay. Each `profile` command prints a link: open it **in Safari**, then
Settings → Profile Downloaded → Install. Browse a few sites after each step, then
run `tests/iphone/run.sh logs`.

| step | command | question |
|---|---|---|
| 0 | `profile iphone-test token` | does the test relay work at all (expect `present=false`) |
| 1 | `profile iphone-test p12 h2` | does iOS send a client certificate over HTTP/2 (hand-made key) |
| 2 | `profile iphone-test p12 h3` | ... over HTTP/3 |
| 3 | `profile iphone-test acme h2` | does an ACME payload install by hand; what the phone sends; certificate over HTTP/2 |
| 4 | `profile iphone-test acme h3` | ... over HTTP/3 |
| 5 | remove the step 4 profile and install the **same link** again | is a second install refused (expect an error on the phone, `refused` in the log) |
| 6 | `profile iphone-test acme-attest both` | does attestation (device serial/UDID from Apple) work without MDM |

If a second iPhone or iPad is at hand, step 5 on that device instead is the real
"a copy on another phone" case.

Note what the phone shows at each step (screenshots of errors help), then:

```sh
tests/iphone/run.sh report      # writes tests/iphone/report.tar.gz: scp it back
tests/iphone/run.sh down        # removes both containers and the test data
```

The report holds the relay and ACME logs. It has no profiles (they contain the
client's token) and no CA key. Afterwards: install the normal relay profile
again, remove the router forwards, and delete the test client.
