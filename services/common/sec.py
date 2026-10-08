"""Security primitives shared by every Portcullis microservice.

Each service imports this module, so session checks, audit publishing and
error handling behave identically everywhere (one place to review).
"""
import hmac
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from psycopg.rows import namedtuple_row
from psycopg_pool import ConnectionPool

import redis

log = logging.getLogger("portcullis")

SERVICE = os.environ["SERVICE"]                      # auth | directory | audit
VERSION = os.environ.get("APP_VERSION", "dev")
POD = socket.gethostname()
SECRETS_DIR = Path(os.environ.get("SECRETS_DIR", "/run/secrets"))

ISSUER, AUDIENCE = "portcullis-auth", "portcullis"
TOKEN_TTL = 900                                       # 15-minute sessions
SESSION_COOKIE, CSRF_COOKIE = "__Host-session", "__Host-csrf"
SAFE_METHODS = {"GET", "HEAD"}
AUDIT_STREAM = "audit:events"


def secret(name: str) -> str:
    """Secrets are mounted as read-only files, never passed as env vars."""
    return (SECRETS_DIR / name).read_text().strip()


JWT_PUBLIC_KEY = secret("jwt_public.pem")

db = ConnectionPool(
    kwargs={
        "host": os.environ.get("DB_HOST", "postgres"),
        "port": int(os.environ.get("DB_PORT", "5432")),
        "dbname": "iam",
        "user": f"{SERVICE}_svc",                    # one least-privilege DB role per service
        "password": secret(f"db_{SERVICE}_password"),
        "connect_timeout": 5,
        "row_factory": namedtuple_row,
    },
    min_size=1,
    max_size=10,
    check=ConnectionPool.check_connection,            # drop dead connections (e.g. after a DB restart) instead of erroring
    open=False,
)

rds = redis.Redis(
    host=os.environ.get("REDIS_HOST", "redis"),
    port=int(os.environ.get("REDIS_PORT", "6379")),
    username=SERVICE,                                 # one Redis ACL user per service
    password=secret(f"redis_{SERVICE}_password"),
    decode_responses=True,
    socket_timeout=3,
    socket_connect_timeout=3,
    health_check_interval=30,
    lib_name=None, lib_version=None,                  # skip CLIENT SETINFO: not in the ACL allow-list
)


def client_ip(request: Request) -> str:
    # Only the gateway can reach services (NetworkPolicy), so its X-Real-IP is trusted.
    raw = request.headers.get("x-real-ip") or (request.client.host if request.client else "")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return "unknown"


def audit(action: str, outcome: str, request: Request | None = None,
          actor: str = "", target: str = "", **detail) -> None:
    """Queue a security event. Raising here makes the caller fail closed."""
    rds.xadd(AUDIT_STREAM, {
        "ts_ms": int(time.time() * 1000),
        "service": SERVICE,
        "action": action,
        "outcome": outcome,
        "actor": actor,
        "target": target,
        "ip": client_ip(request) if request else "",
        "detail": json.dumps(detail, sort_keys=True),
    })


def require(roles: set[str] | None = None, mfa: bool = False):
    """FastAPI dependency: deny by default unless the session passes every check."""
    def check(request: Request) -> dict:
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            raise HTTPException(401, "Not signed in")
        try:
            claims = jwt.decode(
                token, JWT_PUBLIC_KEY,
                algorithms=["EdDSA"],                 # pinned: blocks alg=none / HS256 key-confusion
                audience=AUDIENCE, issuer=ISSUER,
                options={"require": ["exp", "iat", "sub", "jti", "name", "role", "amr", "gen", "csrf"]},
            )
        except jwt.PyJWTError:
            raise HTTPException(401, "Invalid or expired session") from None
        revoked, gen = rds.mget(f"revoked:{claims['jti']}", f"gen:{claims['sub']}")
        if revoked or claims["gen"] != int(gen or 0):
            raise HTTPException(401, "Session has been revoked")
        if request.method not in SAFE_METHODS and not hmac.compare_digest(
                request.headers.get("x-csrf-token", "").encode(), claims["csrf"].encode()):
            raise HTTPException(403, "CSRF check failed")
        if roles and claims["role"] not in roles:
            raise HTTPException(403, "You do not have permission for this action")
        if mfa and "otp" not in claims["amr"]:
            raise HTTPException(403, "This action needs an MFA-verified session")
        return claims
    return check


def create_app(worker=None) -> FastAPI:
    """worker: optional fn(stop_event) run in a background thread (the audit consumer)."""
    @asynccontextmanager
    async def lifespan(_app):
        db.open()
        stop = threading.Event()
        if worker:
            threading.Thread(target=worker, args=(stop,), daemon=True).start()
        yield
        stop.set()
        db.close()

    # API docs are disabled so the attack surface isn't published.
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def invalid_input(_request, exc: RequestValidationError):
        # FastAPI's default 422 echoes the submitted values back (including passwords).
        fields = sorted({".".join(str(p) for p in e["loc"][1:]) or "body" for e in exc.errors()})
        return JSONResponse({"detail": f"Invalid input: {', '.join(fields)}"}, status_code=422)

    @app.exception_handler(Exception)
    async def unexpected(_request, _exc: Exception):
        log.exception("unhandled error")
        return JSONResponse({"detail": "Internal error"}, status_code=500)  # no stack traces leak

    @app.get("/healthz")                              # liveness: process is up
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")                               # readiness: dependencies reachable
    def readyz():
        with db.connection() as conn:
            conn.execute("SELECT 1")
        rds.ping()
        return {"status": "ready"}

    return app
