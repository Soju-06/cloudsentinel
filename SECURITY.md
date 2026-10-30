# Security model

CloudSentinel is a **local-first** lab: it runs on your own machine, stores
alerts in a local SQLite file and is meant to be reached from your own phone on
your own Wi-Fi. This document describes exactly what the API protects, what it
does not, and how to run it without leaving a door open.

If you only read one line: **bind to localhost by default, use a token, add TLS
before you expose the port to a network, and never port-forward it to the
internet.**

---

## 1. Defaults

| Control | Default | Change it with |
|---|---|---|
| Bind address | `127.0.0.1` (this machine only) | `serve --host 0.0.0.0` |
| Authentication | required as soon as any token exists | `--token`, `tokens add` |
| Token transport | `X-API-Token` or `Authorization: Bearer` | — |
| Rate limit | 120 req/min per client + token | `--rate-limit N`, `CLOUDSENTINEL_RATE_LIMIT` |
| Scan rate limit | 1/10th of the general limit (12/min by default) | derived from `--rate-limit` |
| `/health` | public, exempt from rate limiting | — |
| CORS | loopback origins only | `--cors ORIGIN[,ORIGIN]`, `--cors '*'` |
| Remote scan | disabled (`403`) | `--allow-scan`, `CLOUDSENTINEL_API_ALLOW_SCAN=true` |
| TLS | off (plain HTTP) | `--tls-cert` + `--tls-key` |
| Error bodies | uniform JSON, no internals | — |

Two rules are enforced in code rather than documented as advice:

1. **A token store on disk means authentication is on.** Revoking the last token
   locks the API instead of silently reopening it. An operator who wants an open
   API must delete `data/api_tokens.json` deliberately.
2. **The scan endpoint is opt-in.** `POST /api/scan` is the only write-shaped
   endpoint and stays disabled unless you ask for it.

---

## 2. Threat model

### In scope

| Threat | Mitigation |
|---|---|
| Someone on the same Wi-Fi reads alert data | token required; TLS available; loopback bind by default |
| Someone guesses or brute-forces the token | 256-bit tokens, constant-time comparison, rate limiting, `401` with `WWW-Authenticate` |
| A leaked token stays valid forever | rotating token store; revoke takes effect on the next request |
| A stolen laptop exposes the token file | only salted SHA-256 fingerprints are stored, never the token |
| A malicious web page calls the API from your browser | CORS restricted to loopback origins by default |
| Credential stuffing / scraping floods the server | per-client sliding-window limit, `429` + `Retry-After` |
| Error messages leak paths, tokens or stack traces | uniform handlers for `422`, `429`, `500`; details only in server logs |
| Clickjacking / MIME sniffing against `/docs` | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| Remote clients trigger repeated scans | scans get a stricter budget and are off by default |

### Out of scope (by design)

- **User accounts.** There is one shared secret per client, not identities. Any
  valid token has full read access to every alert and its evidence.
- **Read auditing.** Requests are logged by uvicorn to the console, not to a
  tamper-evident audit trail.
- **Multi-tenant isolation.** One database, one owner.
- **Internet exposure.** There is no account lockout, CAPTCHA, WAF or DDoS
  protection. Use a VPN or an authenticated reverse proxy if you need remote
  access.
- **Encryption at rest.** The SQLite database and the token store are plain
  files protected by your OS account. Use BitLocker/FileVault if that matters.
- **The Streamlit console.** `dashboard.py` has no login at all; it is a local
  analyst tool. Do not publish port 8501.

The rate limiter is **per process**. That is correct for the intended
single-process deployment; running multiple uvicorn workers would require a
shared store (Redis) and the limiter is written as the seam to replace.

---

## 3. Authentication and token rotation

### Bootstrap token

```powershell
python -m cloudsentinel serve --host 0.0.0.0 --token CHANGE_ME
```

Quick and fine for a demo, but every client shares one value and rotating it
means restarting the server and re-entering it everywhere.

### Rotating tokens (recommended)

```powershell
python -m cloudsentinel tokens add --label phone
# New API token — shown once, store it now:
#   Xy7... (43 characters)

python -m cloudsentinel tokens list
# LABEL   FINGERPRINT  CREATED                STATE
# phone   a1b2c3d4     2026-10-30T12:00:00Z   active

python -m cloudsentinel tokens revoke phone
```

- Tokens are 32 random bytes (`secrets.token_urlsafe`), printed **once**.
- Only a salted SHA-256 fingerprint is written to `data/api_tokens.json`. The
  file is gitignored and receives owner-only permissions on POSIX systems.
- Verification compares every active digest in constant time, so timing does not
  reveal which token matched.
- `revoke` accepts a label, a label prefix or a fingerprint prefix, and applies
  on the **next request** — no restart.

### Rotation runbook

1. `tokens add --label phone-2026-11` → enter the new token on the phone.
2. Confirm the phone connects.
3. `tokens revoke phone` (or the older label).
4. If a token leaked: revoke it first, then add a replacement. If you were using
   only `--token`, restart with a new value and update every client.

The store path can be moved with `--token-file` or `CLOUDSENTINEL_TOKEN_FILE`.
Deleting the file removes stored tokens (and, with no `--token`, opens the API —
do this only on localhost).

---

## 4. HTTPS

The API terminates TLS itself, so no reverse proxy and no administrator rights
are needed:

```powershell
python scripts\make_dev_cert.py --out certs
python -m cloudsentinel serve --host 0.0.0.0 --port 8443 --token CHANGE_ME `
  --tls-cert certs\cloudsentinel-dev.pem --tls-key certs\cloudsentinel-dev-key.pem
```

The generator creates one self-signed CA/server certificate (RSA-2048, SHA-256,
825 days by default) with subject alternative names for `localhost`, the machine
name, `127.0.0.1`, `::1` and the detected LAN address. Add more with `--ip` and
`--dns`; `--force` replaces an existing pair. `certs/` is gitignored — never
commit the key.

| Client | Trust step |
|---|---|
| Windows app (WebView2) and browsers | `certutil -user -addstore Root certs\cloudsentinel-dev.pem` |
| Android browser | Settings → Security → Encryption & credentials → Install a certificate → CA certificate |
| Python / curl | `--cacert certs\cloudsentinel-dev.pem` |

**Known limitation — Android app over HTTPS:** Flutter's HTTP stack does not
read the Android user CA store, so the self-signed certificate is rejected by the
APK even after installing it. Options:

- keep HTTP on a trusted home Wi-Fi (the default LAN assumption), or
- put a publicly trusted certificate in front of the API (Caddy + Let's Encrypt
  with a real domain), or
- ship a debug build with a pinned certificate (not supported out of the box).

HTTPS still matters for Windows, browsers, curl and any future client, and it is
the right answer as soon as the traffic crosses a network you do not control.

---

## 5. Rate limiting

Every `/api/*` request counts against a sliding 60-second window keyed by client
address plus a truncated hash of the presented token. `/health` is exempt so
monitoring keeps working during an incident.

```
HTTP/1.1 429 Too Many Requests
retry-after: 37
{"detail": "rate limit exceeded", "retry_after": 37}
```

- `--rate-limit 0` disables limiting (useful for benchmarks; do not use it on a
  network).
- The scan budget is `max(1, limit // 10)`.
- Memory is bounded: at most 4096 client keys are tracked, evicted least-recently
  used.

---

## 6. Deployment guidance

| Scenario | Recommended command |
|---|---|
| Local development | `python -m cloudsentinel serve` |
| Local console + Windows app | `serve --port 8080 --token SECRET` |
| Phone on trusted Wi-Fi (HTTP) | `serve --host 0.0.0.0 --token SECRET` |
| Phone on shared/office Wi-Fi | add `--tls-cert/--tls-key`, install the CA on each device |
| Remote access | VPN into the LAN, or an authenticated reverse proxy with a public certificate |
| Anything internet-facing | don't expose this API; use a VPN |

Checklist before you type `--host 0.0.0.0`:

- [ ] A token exists (`--token` or `tokens add`), and it is not `CHANGE_ME`.
- [ ] Windows Firewall allows Python on **Private** networks only.
- [ ] TLS is configured if the Wi-Fi is not yours.
- [ ] `--allow-scan` is off unless you need the in-app scan button.
- [ ] The Streamlit console (8501) is not exposed.
- [ ] `certs/` and `data/api_tokens.json` are outside version control.

### Response headers

Every response carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. OpenAPI docs remain
available at `/docs` — convenient on localhost, another reason not to expose the
port publicly.

---

## 7. Verifying a deployment

```powershell
# No token: must be 401
curl.exe -i http://127.0.0.1:8080/api/summary

# Valid token: 200
curl.exe -i -H "X-API-Token: YOUR_TOKEN" http://127.0.0.1:8080/api/summary

# Health: 200, public, shows the posture
curl.exe -s http://127.0.0.1:8080/health

# Sixth request inside a rate-limited window: 429 with Retry-After
```

The startup banner repeats the posture (`TLS`, `Authentication`, `Rate limit`)
and prints a warning whenever the API is bound to a network interface without
TLS or without a token.

Automated coverage for all of the above lives in `tests/test_security.py`
(36 tests, 1 skipped on Windows: token store, rotation, headers, CORS, rate limits, TLS flags,
certificate generation).
