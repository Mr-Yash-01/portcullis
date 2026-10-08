"""auth service: registration, login, TOTP MFA, sessions and logout."""
import base64
import hmac
import os
import secrets
import struct
import threading
import time
from pathlib import Path
from typing import Annotated

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from common.sec import (
    AUDIENCE,
    CSRF_COOKIE,
    ISSUER,
    POD,
    SESSION_COOKIE,
    TOKEN_TTL,
    VERSION,
    audit,
    client_ip,
    create_app,
    db,
    rds,
    require,
    secret,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, HTTPException, Request, Response
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, ConfigDict, StringConstraints

app = create_app()

ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)  # OWASP Argon2id baseline
HASH_SLOTS = threading.BoundedSemaphore(4)    # each hash needs 19 MiB; caps RAM under a login flood
JWT_PRIVATE_KEY = secret("jwt_private.pem")
MFA_KEY = AESGCM(bytes.fromhex(secret("mfa_key")))
DUMMY_HASH = ph.hash(secrets.token_hex(16))   # verified for unknown users so timing doesn't leak existence
# 46k leaked passwords of 12+ chars (SecLists xato-net 1M list), lower-cased.
COMMON_PASSWORDS = set(Path(__file__).with_name("common-passwords.txt").read_text().splitlines())
MAX_USER_FAILS, MAX_IP_FAILS, FAIL_WINDOW = 5, 20, 900

Username = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_.-]{3,32}$")]
Password = Annotated[str, StringConstraints(min_length=12, max_length=128)]
TotpCode = Annotated[str, StringConstraints(pattern=r"^[0-9]{6}$")]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown fields rejected: no mass assignment


class Register(Strict):
    username: Username
    password: Password


class Login(Strict):
    username: Username
    password: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    totp: TotpCode | None = None


class Code(Strict):
    code: TotpCode


# ---------- password hashing ----------

def _with_slot(fn, *args):
    if not HASH_SLOTS.acquire(timeout=5):
        raise HTTPException(503, "Server busy, please retry")
    try:
        return fn(*args)
    finally:
        HASH_SLOTS.release()


def hash_password(password: str) -> str:
    return _with_slot(ph.hash, password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _with_slot(ph.verify, stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def password_problem(username: str, password: str) -> str | None:
    if password.lower() in COMMON_PASSWORDS:
        return "This password is in a list of commonly used passwords"
    if username in password.lower():
        return "Password must not contain your username"
    return None


# ---------- TOTP (RFC 6238) ----------

def totp(key: bytes, step: int) -> str:
    mac = hmac.new(key, struct.pack(">Q", step), "sha1").digest()
    offset = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def check_totp(uid: int, key: bytes, code: str) -> bool:
    now = int(time.time()) // 30
    for step in (now - 1, now, now + 1):                       # ±30 s clock drift
        if hmac.compare_digest(totp(key, step), code):
            # Single use: a code seen over someone's shoulder can't be replayed.
            return bool(rds.set(f"totp:{uid}:{step}", 1, nx=True, ex=120))
    return False


def seal(uid: int, raw: bytes) -> bytes:
    """MFA secrets are encrypted at rest; the AAD ties each ciphertext to its user row."""
    nonce = os.urandom(12)
    return nonce + MFA_KEY.encrypt(nonce, raw, f"mfa:{uid}".encode())


def unseal(uid: int, blob: bytes) -> bytes:
    return MFA_KEY.decrypt(blob[:12], blob[12:], f"mfa:{uid}".encode())


# ---------- brute-force protection ----------

def reserve_attempt(username: str, ip: str) -> bool:
    """Count the attempt BEFORE checking the password so parallel guesses can't race the limit."""
    pipe = rds.pipeline()
    for key in (f"fail:u:{username}", f"fail:ip:{ip}"):
        pipe.incr(key)
        pipe.expire(key, FAIL_WINDOW)
    user_n, _, ip_n, _ = pipe.execute()
    return user_n <= MAX_USER_FAILS and ip_n <= MAX_IP_FAILS


def refund_attempt(username: str, ip: str, clear_user: bool) -> None:
    pipe = rds.pipeline()
    if clear_user:
        pipe.delete(f"fail:u:{username}")
    else:
        pipe.decr(f"fail:u:{username}")
        pipe.expire(f"fail:u:{username}", FAIL_WINDOW)
    pipe.decr(f"fail:ip:{ip}")
    pipe.expire(f"fail:ip:{ip}", FAIL_WINDOW)
    pipe.execute()


def issue_session(response: Response, uid: int, name: str, role: str, amr: list[str]) -> None:
    now = int(time.time())
    csrf = secrets.token_urlsafe(32)
    token = jwt.encode({
        "iss": ISSUER, "aud": AUDIENCE, "sub": str(uid), "name": name, "role": role,
        "amr": amr, "gen": int(rds.get(f"gen:{uid}") or 0), "csrf": csrf,
        "jti": secrets.token_urlsafe(16), "iat": now, "exp": now + TOKEN_TTL,
    }, JWT_PRIVATE_KEY, algorithm="EdDSA")
    for cookie, value, http_only in ((SESSION_COOKIE, token, True), (CSRF_COOKIE, csrf, False)):
        response.set_cookie(cookie, value, max_age=TOKEN_TTL, path="/", secure=True,
                            httponly=http_only, samesite="strict")


# ---------- endpoints ----------

@app.post("/api/auth/register", status_code=201)
def register(req: Register, request: Request):
    if problem := password_problem(req.username, req.password):
        raise HTTPException(400, problem)
    password_hash = hash_password(req.password)
    try:
        with db.connection() as conn:   # the audit event is queued inside the transaction: no event, no account
            conn.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                         (req.username, password_hash))
            audit("user_registered", "success", request, actor=req.username, target=req.username)
    except UniqueViolation:
        raise HTTPException(409, "That username is not available") from None
    return {"status": "registered"}


@app.post("/api/auth/login")
def login(req: Login, request: Request, response: Response):
    ip = client_ip(request)
    if not reserve_attempt(req.username, ip):
        audit("login_blocked", "denied", request, target=req.username)
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")

    with db.connection() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash, role, status, mfa_enabled, mfa_secret"
            " FROM users WHERE username = %s", (req.username,)).fetchone()

    def fail(reason: str, message: str):
        audit("login_failed", "denied", request, target=req.username, reason=reason)
        if int(rds.get(f"fail:u:{req.username}") or 0) == MAX_USER_FAILS:
            audit("account_locked", "denied", request, target=req.username)
        raise HTTPException(401, message)

    password_ok = verify_password(user.password_hash if user else DUMMY_HASH, req.password)
    if not (user and password_ok and user.status == "active"):
        # Same message and timing for unknown user, wrong password and disabled account.
        fail("credentials", "Invalid username or password")

    amr = ["pwd"]
    if user.mfa_enabled:
        if req.totp is None:
            refund_attempt(req.username, ip, clear_user=False)  # not a failure, but no counter reset either
            return {"mfa_required": True}
        if not check_totp(user.id, unseal(user.id, user.mfa_secret), req.totp):
            fail("mfa", "Invalid or already-used MFA code")
        amr.append("otp")

    refund_attempt(req.username, ip, clear_user=True)
    with db.connection() as conn:
        if ph.check_needs_rehash(user.password_hash):   # transparently upgrade old hash parameters
            conn.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                         (hash_password(req.password), user.id))
        conn.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (user.id,))
        audit("login_success", "success", request, actor=user.username, target=user.username, mfa=user.mfa_enabled)
    issue_session(response, user.id, user.username, user.role, amr)
    return {"status": "signed_in"}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, s: dict = Depends(require())):
    rds.set(f"revoked:{s['jti']}", 1, ex=max(1, s["exp"] - int(time.time())))
    audit("logout", "success", request, actor=s["name"], target=s["name"])
    for cookie, http_only in ((SESSION_COOKIE, True), (CSRF_COOKIE, False)):
        response.delete_cookie(cookie, path="/", secure=True, httponly=http_only, samesite="strict")
    return {"status": "signed_out"}


@app.get("/api/auth/me")
def me(s: dict = Depends(require())):
    with db.connection() as conn:
        user = conn.execute("SELECT username, role, mfa_enabled, created_at, last_login_at"
                            " FROM users WHERE id = %s", (int(s["sub"]),)).fetchone()
    if not user:
        raise HTTPException(401, "Account no longer exists")
    return {"username": user.username, "role": user.role, "mfa_enabled": user.mfa_enabled,
            "mfa_session": "otp" in s["amr"], "session_expires": s["exp"],
            "created_at": user.created_at, "last_login_at": user.last_login_at,
            "served_by": {"service": "auth", "version": VERSION, "pod": POD}}


@app.post("/api/auth/mfa/setup")
def mfa_setup(s: dict = Depends(require())):
    uid = int(s["sub"])
    raw = secrets.token_bytes(20)                                # 160-bit secret (RFC 4226)
    with db.connection() as conn:
        updated = conn.execute("UPDATE users SET mfa_secret = %s WHERE id = %s AND NOT mfa_enabled",
                               (seal(uid, raw), uid)).rowcount
    if not updated:
        raise HTTPException(409, "MFA is already enabled")
    key = base64.b32encode(raw).decode()
    return {"secret": key, "uri": f"otpauth://totp/Portcullis:{s['name']}?secret={key}&issuer=Portcullis"}


@app.post("/api/auth/mfa/enable")
def mfa_enable(req: Code, request: Request, response: Response, s: dict = Depends(require())):
    uid = int(s["sub"])
    with db.connection() as conn:
        user = conn.execute("SELECT mfa_secret, mfa_enabled FROM users WHERE id = %s", (uid,)).fetchone()
        if not user or user.mfa_enabled or user.mfa_secret is None:
            raise HTTPException(409, "Start MFA setup first")
        if not check_totp(uid, unseal(uid, user.mfa_secret), req.code):
            raise HTTPException(400, "That code is not valid")
        conn.execute("UPDATE users SET mfa_enabled = true WHERE id = %s", (uid,))
        audit("mfa_enabled", "success", request, actor=s["name"], target=s["name"])
        rds.incr(f"gen:{uid}")                    # sign out every other session that lacked MFA
    issue_session(response, uid, s["name"], s["role"], ["pwd", "otp"])
    return {"status": "mfa_enabled"}
