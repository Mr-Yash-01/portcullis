# Portcullis security design

Defence in depth: every request passes through five independent layers, and every layer assumes the
one in front of it has already failed.

```
Edge (Cloud Armor + HTTPS LB) → Gateway (nginx) → Application (FastAPI) → Data (Postgres/Redis) → Platform (GKE)
```

Every claim below is checked by `tests/security_test.py` (local stack) or a command in the README's
"Security checks to show" section.

## Controls mapped to the OWASP Top 10:2025

| OWASP 2025 | Threat | Control | Where |
|---|---|---|---|
| **A01 Broken Access Control** | User calls admin APIs | Deny-by-default `require()` check on every endpoint; roles user/auditor/admin; admin and auditor tools also require an **MFA-verified** session | `common/sec.py`, `directory/main.py`, `audit/main.py` |
| | Privilege escalation via request body (mass assignment) | Pydantic models with `extra="forbid"`; `role` is not a registration field | `auth/main.py` |
| | Self-promotion, or demoting the last admin | Admins cannot change their own account; no service DB role can grant `admin` at signup | `directory/main.py`, `db/init.sh` |
| | Stale privileges after a role change | Per-user session generation counter: changing role/status or enabling MFA instantly revokes all of that user's sessions | `gen:{uid}` in Redis |
| | Cross-site request forgery | `SameSite=Strict` cookies **plus** signed double-submit token: the CSRF value lives inside the signed session and must match the `X-CSRF-Token` header | `issue_session`, `require()` |
| **A02 Security Misconfiguration** | Verbose errors / stack traces | Generic 500 handler; validation errors list field names only (FastAPI's default echoes inputs, including passwords) | `create_app()` |
| | Exposed API docs / version banners | OpenAPI/Swagger disabled; `server_tokens off`; uvicorn `--no-server-header` | |
| | Browser-side attacks | Strict CSP (`script-src 'self'`, no inline code, **Trusted Types required**), HSTS, `X-Frame-Options DENY`, `frame-ancestors 'none'`, `nosniff`, `no-referrer`, COOP/CORP, Permissions-Policy | `gateway/nginx.conf` |
| | Over-privileged containers | Restricted Pod Security admission; non-root UIDs, read-only root filesystem, all Linux capabilities dropped, no privilege escalation, seccomp `RuntimeDefault`, no service-account token | `k8s/*` |
| | Lateral movement inside the cluster | Default-deny NetworkPolicies, ingress and egress, enforced by Dataplane V2: only gateway→APIs→datastores flows exist | `k8s/40-network-policies.yaml` |
| | Cloud credential theft via SSRF | Egress deny blocks the metadata server (169.254.169.254); nodes use a minimal service account, not Editor | README 2.2 |
| **A03 Software Supply Chain Failures** | Malicious or typo-squatted packages | Every Python dependency pinned **with SHA-256 hashes** (`pip --require-hashes`); minimal dependency set (TOTP is 10 lines of stdlib, not a library) | `services/requirements.txt` |
| | Untrusted base images | Exact image tags; images stored in a private Artifact Registry repo that nodes can only read | Dockerfiles, README 2.4 |
| **A04 Cryptographic Failures** | Password cracking after a DB leak | **Argon2id** (OWASP parameters: m=19 MiB, t=2, p=1), auto-rehash when parameters change | `auth/main.py` |
| | MFA secrets leaked from the DB | Encrypted at rest with **AES-256-GCM**; the user ID is bound as associated data, so ciphertexts can't be swapped between users | `seal()` / `unseal()` |
| | Token forgery | Sessions signed with **Ed25519** (EdDSA). Only `auth` holds the private key; the others can verify but not mint. Algorithm pinned, so `alg=none` and HS256 key-confusion attacks fail (both tested) | `common/sec.py` |
| | Eavesdropping | HTTPS only: Google-managed certificate, HTTP→HTTPS redirect, TLS 1.2+ `MODERN` SSL policy, HSTS; cookies are `Secure` and `__Host-` prefixed | `k8s/30-gateway.yaml` |
| | Weak randomness | `secrets` / `os.urandom` / OpenSSL for all tokens, keys and passwords | |
| **A05 Injection** | SQL injection | Only parameterised queries; strict input patterns; `LIKE` wildcards escaped; Cloud Armor CRS `sqli` rule at the edge | everywhere |
| | Cross-site scripting | UI never uses `innerHTML` (DOM nodes + `textContent` only); Trusted Types turns any future mistake into a blocked error; strict username charset; CRS `xss` rule | `gateway/static/app.js` |
| | Header / IP spoofing | Client IP read from the entry Google's LB appends to `X-Forwarded-For`; client-supplied `X-Forwarded-For` is stripped before the services | `gateway/nginx.conf` |
| **A06 Insecure Design** | Unbounded resource use (DoS) | Rate limits at 3 layers (Cloud Armor per-IP ban, nginx per-IP `limit_req`/`limit_conn`, app lockout); 16 KB bodies; slowloris timeouts; Argon2 concurrency capped per pod (bounded RAM); DB statement timeouts and connection limits; CPU/memory limits on every pod | |
| | Single point of failure | ≥2 replicas per service spread across nodes, PodDisruptionBudgets, autoscaling, zero-downtime rolling updates | `k8s/2*.yaml` |
| **A07 Authentication Failures** | Brute force / password spraying | Per-account (5) and per-IP (20) failure limits over 15 min. The attempt is counted *before* the password is checked, so parallel guesses can't race the limit. Admins can unlock | `reserve_attempt()` |
| | Credential stuffing | 46k leaked passwords (12+ chars) blocked; 12–128 character passphrases (NIST 800-63B style: length over complexity rules); password may not contain the username | `common-passwords.txt` |
| | User enumeration | Identical error, status and timing for unknown user / wrong password / disabled account (a dummy Argon2 hash is verified for unknown users); non-existent usernames lock out just like real ones | `login()` |
| | Weak second factor | TOTP (RFC 6238) with 160-bit secrets; **each code is single-use** (replay rejected); MFA guesses count toward lockout; enrolment needs a valid code first | `check_totp()` |
| | Session hijacking | 15-minute sessions; `HttpOnly` (not readable by JS), `Secure`, `SameSite=Strict`, `__Host-` prefix; **server-side revocation** on logout (stolen tokens stop working: tested) | `logout()` |
| **A08 Software or Data Integrity Failures** | Audit log tampering | Append-only DB role (no UPDATE/DELETE); each row stores SHA-256(previous hash ‖ event), so editing or deleting any row breaks the chain; `/api/audit/verify` pinpoints the first altered event (tested) | `audit/main.py` |
| | Lost or duplicated events | Redis Stream with consumer group, ack after commit, crashed-consumer reclaim (`XAUTOCLAIM`), idempotent insert by stream ID; Redis AOF persistence | `audit/main.py` |
| **A09 Security Logging & Alerting Failures** | Attacks go unnoticed | Every security event logged (sign-in ok/failed/blocked, lockout, registration, role/status change, unlock, MFA, logout) with actor, target and IP; dashboard of 24 h counts and top failing IPs; LB request logging at the edge | Security log tab |
| | Logged actions that never happened, or actions with no log | Audit events are queued inside the DB transaction: if the event can't be queued, the change is rolled back (fail closed) | `register()`, `update_user()` |
| **A10 Mishandling of Exceptional Conditions** | Fail-open on dependency errors | Redis or DB failure → request fails (no session issued, no change made). Redis uses `noeviction`, so revocations/lockouts are never silently dropped. Readiness probes pull broken pods out of the load balancer | `redis/redis.conf`, `/readyz` |

## Least privilege at the data layer

| Principal | Postgres | Redis keys | Commands |
|---|---|---|---|
| `auth` | `users`: SELECT credential columns, INSERT username+hash only, UPDATE hash/MFA/last-login only | `fail:* totp:* revoked:* gen:* audit:events` | get set incrby decrby del expire mget xadd multi exec |
| `directory` | `users`: SELECT profile columns (**no** hash/secret), UPDATE role/status only | `fail:* revoked:* gen:* audit:events` | mget del incrby xadd |
| `audit` | `audit_events`: SELECT, INSERT only | `revoked:* gen:* audit:events` | mget + stream consumer commands |
| Redis `default` user | — | disabled | — |

So, for example, an SQL-injection bug in `directory` still couldn't read a single password hash, and a
compromised `audit` pod couldn't erase the evidence.

## Residual risks and next steps (out of scope for this project)

- **Single Postgres/Redis replica.** Data survives restarts (persistent disks), but a datastore node failure means ~1 minute of downtime. Production: Cloud SQL HA + Memorystore with replicas.
- **In-cluster traffic is not encrypted.** NetworkPolicies restrict who can talk; a service mesh (mTLS) would encrypt it.
- **Kubernetes Secrets** are encrypted at rest by GKE by default. Production: Cloud KMS application-layer encryption or Secret Manager, and key rotation.
- **Account lockout can be abused** to lock a victim out (a known trade-off). Mitigated by admin unlock and the 15-minute expiry. Production: CAPTCHA / risk-based step-up instead of hard lockout.
- **No password reset or MFA recovery flow** (would need verified email); an admin can disable and recreate an account.
- **Hash chain anchoring.** A database superuser could rewrite the entire chain consistently. Production: periodically publish the latest hash to write-once storage (e.g. a locked Cloud Storage bucket).
- **Local docker-compose has no load balancer**, so there a client can spoof `X-Forwarded-For`. In GKE only Google's LB can reach the gateway.
- Not added: Binary Authorization, private nodes + Cloud NAT, vulnerability scanning in CI, WebAuthn/passkeys.
