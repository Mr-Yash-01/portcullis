#!/usr/bin/env python3
"""End-to-end functional + attack tests for Portcullis (Python standard library only).

Usage:
  BASE=http://localhost:8080 PSQL='docker compose exec -T postgres psql -U postgres -d iam -tAc' \
    python3 tests/security_test.py

PSQL must run one SQL statement as the Postgres superuser: the tests need it to create the
first admin (deliberately impossible through the API) and to simulate an attacker editing
the audit table directly.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import shlex
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("BASE", "http://localhost:8080").rstrip("/")
assert BASE.startswith(("http://", "https://")), "BASE must be an http(s) URL"
PSQL = shlex.split(os.environ.get("PSQL", "docker compose exec -T postgres psql -U postgres -d iam -tAc"))
RUN = secrets.token_hex(3)                    # unique usernames, so the suite can be re-run
NET = secrets.randbelow(250)                  # fresh simulated client IPs per run (rate limits are per IP)
PASSWORD = "correct horse battery staple " + RUN
failures = 0


def check(name: str, ok: bool, info="") -> None:
    global failures
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'' if ok else f'  -> {info}'}")


def sql(statement: str) -> str:
    return subprocess.run(PSQL + [statement], check=True, capture_output=True, text=True).stdout.strip()


def ip(host) -> str:
    return f"198.18.{NET}.{host}"


def totp(key_b32: str, step: int | None = None) -> str:
    key = base64.b32decode(key_b32)
    step = int(time.time()) // 30 if step is None else step
    mac = hmac.new(key, struct.pack(">Q", step), "sha1").digest()
    o = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


class Client:
    """Tiny HTTP client with a manual cookie jar (stdlib jars refuse Secure cookies over http)."""

    def __init__(self, ip: str):
        self.jar: dict[str, str] = {}
        self.ip = ip                              # simulated client IP via the LB-style X-Forwarded-For

    def call(self, method, path, body=None, csrf=True, headers=None, raw=None):
        h = {"Content-Type": "application/json", "X-Forwarded-For": f"{self.ip}, 10.0.0.1"}
        if self.jar:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.jar.items())
        if csrf and "__Host-csrf" in self.jar:
            h["X-CSRF-Token"] = self.jar["__Host-csrf"]
        h.update(headers or {})
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)  # noqa: S310 - scheme checked above
        try:
            resp = urllib.request.urlopen(req, timeout=20)  # noqa: S310 - scheme checked above
        except urllib.error.HTTPError as e:
            resp = e
        self.last_cookies = resp.headers.get_all("Set-Cookie") or []
        for sc in self.last_cookies:
            name, _, rest = sc.partition("=")
            value = rest.split(";")[0].strip('"')
            if "max-age=0" in sc.lower() or not value:
                self.jar.pop(name, None)
            else:
                self.jar[name] = value
        text = resp.read().decode(errors="replace")
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        return resp.status, payload, resp.headers


def wait_for_event(client: Client, action: str, target: str, timeout=15) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, data, _ = client.call("GET", f"/api/audit/events?action={action}")
        if data and any(e["target"] == target for e in data["events"]):
            return True
        time.sleep(1)
    return False


def main() -> None:
    # RFC 6238 Appendix B vector, so our test TOTP generator is itself known-good.
    key = base64.b32encode(b"12345678901234567890").decode()
    check("TOTP generator matches RFC 6238 vector", totp(key, 59 // 30) == "287082" and totp(key, 1111111109 // 30) == "081804")

    alice, bob, carol = f"alice{RUN}", f"bob{RUN}", f"carol{RUN}"
    def anon() -> Client:  # one-off client from a random IP
        return Client(f"10.{secrets.randbelow(250)}.{secrets.randbelow(250)}.{secrets.randbelow(250)}")

    a, b, c, mallory = Client(ip(1)), Client(ip(2)), Client(ip(3)), Client(ip(66))

    # --- gateway hardening ---
    status, _, h = a.call("GET", "/")
    check("UI served", status == 200)
    csp = h.get("Content-Security-Policy", "")
    check("CSP: no inline script, Trusted Types, no framing",
          "script-src 'self'" in csp and "require-trusted-types-for 'script'" in csp and "frame-ancestors 'none'" in csp, csp)
    check("HSTS / nosniff / no-referrer headers",
          "max-age" in h.get("Strict-Transport-Security", "") and h.get("X-Content-Type-Options") == "nosniff"
          and h.get("Referrer-Policy") == "no-referrer")
    check("nginx version hidden", h.get("Server") == "nginx", h.get("Server"))
    check("DELETE method rejected (405)", a.call("DELETE", "/api/auth/me")[0] == 405)
    check("Oversized body rejected (413)", a.call("POST", "/api/auth/login", raw=b"x" * 20_000)[0] == 413)
    check("Internal /readyz not reachable through gateway", a.call("GET", "/api/auth/../readyz")[0] in (400, 404))
    check("Unknown API path 404", a.call("GET", "/api/admin/secret")[0] == 404)

    # --- registration & input validation ---
    status, data, _ = anon().call("POST", "/api/auth/register", {"username": alice, "password": "short"})
    check("Short password rejected without echoing it back", status == 422 and "short" not in json.dumps(data), data)
    status, data, _ = anon().call("POST", "/api/auth/register", {"username": alice, "password": "password1234"})
    check("Leaked/common password rejected", status == 400, data)
    status, data, _ = anon().call("POST", "/api/auth/register", {"username": alice, "password": alice + "-secret-x"})
    check("Password containing username rejected", status == 400, data)
    status, _, _ = anon().call("POST", "/api/auth/register", {"username": alice, "password": PASSWORD, "role": "admin"})
    check("Mass assignment (role=admin on register) rejected", status == 422)
    status, _, _ = anon().call("POST", "/api/auth/register", {"username": "x' OR '1'='1", "password": PASSWORD})
    check("SQL-injection-shaped username rejected", status == 422)
    status, _, _ = anon().call("POST", "/api/auth/register", {"username": "<script>", "password": PASSWORD})
    check("XSS-shaped username rejected", status == 422)
    for user, cl in ((alice, a), (bob, b), (carol, c)):
        status, data, _ = cl.call("POST", "/api/auth/register", {"username": user, "password": PASSWORD})
        check(f"Register {user}", status == 201, data)
    check("Duplicate username rejected (409)",
          anon().call("POST", "/api/auth/register", {"username": alice, "password": PASSWORD})[0] == 409)

    # --- login, enumeration resistance, cookies ---
    s1, d1, _ = mallory.call("POST", "/api/auth/login", {"username": alice, "password": "wrong-password-1"})
    s2, d2, _ = mallory.call("POST", "/api/auth/login", {"username": f"ghost{RUN}", "password": "wrong-password-1"})
    check("Wrong password and unknown user give identical errors", (s1, d1) == (s2, d2) == (401, {"detail": "Invalid username or password"}), (d1, d2))
    status, _, _ = a.call("POST", "/api/auth/login", {"username": alice, "password": PASSWORD})
    flags = " ".join(a.last_cookies).lower()
    check("Login succeeds", status == 200)
    check("Session cookie is __Host-, HttpOnly, Secure, SameSite=Strict",
          any(ck.startswith("__Host-session=") and "httponly" in ck.lower() for ck in a.last_cookies)
          and "secure" in flags and "samesite=strict" in flags, a.last_cookies)
    status, me, _ = a.call("GET", "/api/auth/me")
    check("/me returns own profile", status == 200 and me["username"] == alice and me["role"] == "user", me)

    # --- session attacks ---
    check("CSRF: state change without token rejected", a.call("POST", "/api/auth/logout", csrf=False)[0] == 403)
    check("CSRF: wrong token rejected",
          a.call("POST", "/api/auth/logout", csrf=False, headers={"X-CSRF-Token": "guess"})[0] == 403)
    real = a.jar["__Host-session"]
    header, payload, sig = real.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged = dict(claims, role="admin", amr=["pwd", "otp"])
    def b64(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    hs_head = b64({"alg": "HS256", "typ": "JWT"})
    hs_sig = hmac.new(open("secrets/jwt_public.pem", "rb").read(), f"{hs_head}.{b64(forged)}".encode(), hashlib.sha256).digest()
    attacks = {
        "tampered payload (role=admin)": f"{header}.{b64(forged)}.{sig}",
        "alg=none": f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(forged)}.",
        "HS256 signed with the public key (key confusion)":
            f"{hs_head}.{b64(forged)}." + base64.urlsafe_b64encode(hs_sig).rstrip(b"=").decode(),
    }
    for name, token in attacks.items():
        evil = Client(ip(66))
        evil.jar = {"__Host-session": token}
        check(f"Forged JWT rejected: {name}", evil.call("GET", "/api/auth/me")[0] == 401)

    # --- RBAC ---
    check("Normal user cannot list users (403)", a.call("GET", "/api/directory/users")[0] == 403)
    check("Normal user cannot read audit log (403)", a.call("GET", "/api/audit/events")[0] == 403)
    check("Anonymous request rejected (401)", mallory.call("GET", "/api/directory/users")[0] == 401)

    # --- MFA ---
    status, setup, _ = a.call("POST", "/api/auth/mfa/setup")
    check("MFA setup returns a 160-bit base32 secret", status == 200 and len(base64.b32decode(setup["secret"])) == 20, setup)
    check("Wrong MFA code rejected on enable", a.call("POST", "/api/auth/mfa/enable", {"code": "000000"})[0] == 400)
    old_jar = dict(a.jar)
    status, _, _ = a.call("POST", "/api/auth/mfa/enable", {"code": totp(setup["secret"])})
    check("MFA enabled with valid code", status == 200)
    stale = Client(ip(1))
    stale.jar = old_jar
    check("Pre-MFA session revoked after enabling MFA", stale.call("GET", "/api/auth/me")[0] == 401)
    a2 = Client(ip(1))
    status, data, _ = a2.call("POST", "/api/auth/login", {"username": alice, "password": PASSWORD})
    check("Login asks for MFA code", status == 200 and data == {"mfa_required": True}, data)
    check("No session issued before MFA", "__Host-session" not in a2.jar)
    code = totp(setup["secret"], int(time.time()) // 30 + 1)   # next step (±1 allowed); current one was just used
    status, _, _ = a2.call("POST", "/api/auth/login", {"username": alice, "password": PASSWORD, "totp": code})
    check("Login with password + TOTP", status == 200 and "__Host-session" in a2.jar)
    replay = Client(ip(1))
    status, _, _ = replay.call("POST", "/api/auth/login", {"username": alice, "password": PASSWORD, "totp": code})
    check("TOTP code replay rejected", status == 401)

    # --- brute force lockout (per account, from rotating IPs so the IP limit isn't what stops it) ---
    for i in range(5):
        Client(ip(i + 10)).call("POST", "/api/auth/login", {"username": bob, "password": f"guess-{i}-wrong"})
    status, data, _ = Client(ip(99)).call("POST", "/api/auth/login", {"username": bob, "password": PASSWORD})
    check("Account locked after 5 failures, even with the right password", status == 429, data)
    for i in range(5):
        Client(ip(i + 50)).call("POST", "/api/auth/login", {"username": f"ghost{RUN}", "password": f"guess-{i}"})
    status, _, _ = Client(ip(98)).call("POST", "/api/auth/login", {"username": f"ghost{RUN}", "password": "guess"})
    check("Non-existent accounts lock the same way (no enumeration via lockout)", status == 429)

    # --- admin bootstrap and admin features ---
    sql(f"UPDATE users SET role = 'admin' WHERE username = '{carol}'")
    c.call("POST", "/api/auth/login", {"username": carol, "password": PASSWORD})
    status, data, _ = c.call("GET", "/api/directory/users")
    check("Admin without MFA session is refused admin tools", status == 403 and "MFA" in data["detail"], data)
    _, setup_c, _ = c.call("POST", "/api/auth/mfa/setup")
    c.call("POST", "/api/auth/mfa/enable", {"code": totp(setup_c["secret"])})
    users = {}
    for name in (alice, bob, carol):
        status, data, _ = c.call("GET", f"/api/directory/users?q={name}")
        users.update({u["username"]: u for u in (data or {}).get("users", [])})
    check("Admin with MFA can list users", status == 200 and alice in users, data)
    check("Directory never returns password hashes or MFA secrets",
          all("password_hash" not in u and "mfa_secret" not in u for u in users.values()))
    check("Locked account shown as locked", users.get(bob, {}).get("locked") is True, users.get(bob))
    check("Search rejects SQL metacharacters", c.call("GET", "/api/directory/users?q=%27%20OR%201=1--")[0] == 422)
    me_c = users[carol]
    check("Admin cannot change own role", c.call("PATCH", f"/api/directory/users/{me_c['id']}", {"role": "user"})[0] == 400)
    check("Unknown fields in admin update rejected",
          c.call("PATCH", f"/api/directory/users/{users[alice]['id']}", {"password_hash": "x"})[0] == 422)
    check("Invalid role value rejected",
          c.call("PATCH", f"/api/directory/users/{users[alice]['id']}", {"role": "root"})[0] == 422)
    status, _, _ = c.call("POST", f"/api/directory/users/{users[bob]['id']}/unlock")
    check("Admin unlocks bob", status == 200)
    status, _, _ = Client(ip(97)).call("POST", "/api/auth/login", {"username": bob, "password": PASSWORD})
    check("Bob can sign in after unlock", status == 200)
    status, _, _ = c.call("PATCH", f"/api/directory/users/{users[alice]['id']}", {"role": "auditor"})
    check("Admin promotes alice to auditor", status == 200)
    check("Alice's live session revoked by the role change", a2.call("GET", "/api/auth/me")[0] == 401)
    c.call("PATCH", f"/api/directory/users/{users[bob]['id']}", {"status": "disabled"})
    status, data, _ = Client(ip(96)).call("POST", "/api/auth/login", {"username": bob, "password": PASSWORD})
    check("Disabled account cannot sign in (generic error)", status == 401 and data["detail"] == "Invalid username or password", data)

    # --- audit log ---
    check("Audit event recorded for role change", wait_for_event(c, "user_updated", alice))
    check("Audit event recorded for lockout", wait_for_event(c, "account_locked", bob))
    status, stats, _ = c.call("GET", "/api/audit/stats")
    check("Security stats available", status == 200 and stats["last_24h"].get("login_failed", 0) >= 5, stats)
    status, v, _ = c.call("GET", "/api/audit/verify")
    check("Audit hash chain verifies", status == 200 and v["valid"] and v["checked"] > 0, v)
    victim = sql("SELECT id FROM audit_events WHERE action = 'user_updated' ORDER BY id DESC LIMIT 1")
    original = sql(f"SELECT actor FROM audit_events WHERE id = {victim}")
    sql(f"UPDATE audit_events SET actor = 'nobody' WHERE id = {victim}")
    status, v, _ = c.call("GET", "/api/audit/verify")
    check("Tampering with an audit row is detected", v["valid"] is False and str(v["broken_at_id"]) == victim, v)
    sql(f"UPDATE audit_events SET actor = '{original}' WHERE id = {victim}")
    check("Chain valid again once restored", c.call("GET", "/api/audit/verify")[1]["valid"])

    # --- logout revokes the token server-side ---
    stolen = dict(c.jar)
    check("Logout", c.call("POST", "/api/auth/logout")[0] == 200 and "__Host-session" not in c.jar)
    thief = Client(ip(66))
    thief.jar = stolen
    check("Stolen token is useless after logout", thief.call("GET", "/api/auth/me")[0] == 401)

    print(f"\n{'ALL TESTS PASSED' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
