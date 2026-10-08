"""directory service: admin user management (roles, enable/disable, unlock).

Its database role can read user profiles but has no privilege on password
hashes or MFA secrets, so a bug here can never leak credentials.
"""
from typing import Annotated, Literal

from common.sec import POD, VERSION, audit, create_app, db, rds, require
from fastapi import Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict

app = create_app()
ADMIN = require(roles={"admin"}, mfa=True)
READER = require(roles={"admin", "auditor"}, mfa=True)
PAGE_SIZE = 50
LOCK_AT = 5          # must match auth's MAX_USER_FAILS


class Patch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["user", "auditor", "admin"] | None = None
    status: Literal["active", "disabled"] | None = None


UserId = Annotated[int, Path(ge=1, le=2**62)]


@app.get("/api/directory/users")
def list_users(s: dict = Depends(READER),
               q: Annotated[str, Query(pattern=r"^[a-z0-9_.-]{0,32}$")] = "",
               page: Annotated[int, Query(ge=1, le=10_000)] = 1):
    prefix = q.replace("_", r"\_") + "%"      # '_' is a LIKE wildcard; match it literally
    with db.connection() as conn:
        rows = conn.execute(
            "SELECT id, username, role, status, mfa_enabled, created_at, last_login_at FROM users"
            " WHERE username LIKE %s ORDER BY id LIMIT %s OFFSET %s",
            (prefix, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE)).fetchall()
    fails = rds.mget([f"fail:u:{r.username}" for r in rows]) if rows else []
    users = [r._asdict() | {"locked": int(f or 0) >= LOCK_AT} for r, f in zip(rows, fails, strict=True)]
    return {"users": users[:PAGE_SIZE], "has_more": len(users) > PAGE_SIZE,
            "served_by": {"service": "directory", "version": VERSION, "pod": POD}}


@app.patch("/api/directory/users/{uid}")
def update_user(uid: UserId, req: Patch, request: Request, s: dict = Depends(ADMIN)):
    if uid == int(s["sub"]):
        raise HTTPException(400, "You cannot change your own role or status")  # also keeps ≥1 admin
    changes = req.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(400, "Nothing to change")
    with db.connection() as conn:
        row = conn.execute(
            "UPDATE users SET role = COALESCE(%s, role), status = COALESCE(%s, status)"
            " WHERE id = %s RETURNING username", (req.role, req.status, uid)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        audit("user_updated", "success", request, actor=s["name"], target=row.username, **changes)
        rds.incr(f"gen:{uid}")       # revoke the user's live sessions so the change applies now
    return {"status": "updated"}


@app.post("/api/directory/users/{uid}/unlock")
def unlock_user(uid: UserId, request: Request, s: dict = Depends(ADMIN)):
    with db.connection() as conn:
        row = conn.execute("SELECT username FROM users WHERE id = %s", (uid,)).fetchone()
    if not row:
        raise HTTPException(404, "User not found")
    rds.delete(f"fail:u:{row.username}")
    audit("user_unlocked", "success", request, actor=s["name"], target=row.username)
    return {"status": "unlocked"}
