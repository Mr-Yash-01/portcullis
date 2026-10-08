"""audit service: consumes security events and stores them in a tamper-evident hash chain.

Its database role may only INSERT and SELECT audit rows (no UPDATE/DELETE), and every
row's hash covers the previous row's hash, so editing history breaks the chain.
"""
import hashlib
import json
import logging
import threading
import time
from typing import Annotated

from common.sec import AUDIT_STREAM, POD, VERSION, create_app, db, rds, require
from fastapi import Depends, Query

import redis

log = logging.getLogger("portcullis.audit")
READER = require(roles={"admin", "auditor"}, mfa=True)
GROUP = "audit-writers"
GENESIS = bytes(32)
FIELDS = ("ts_ms", "service", "action", "outcome", "actor", "target", "ip", "detail")


def chain_hash(prev: bytes, record: dict) -> bytes:
    canonical = json.dumps([int(record["ts_ms"])] + [record[f] for f in FIELDS[1:]], separators=(",", ":"))
    return hashlib.sha256(prev + canonical.encode()).digest()


def store(msg_id: str, event: dict) -> None:
    with db.connection() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(4208)")    # one writer at a time keeps the chain linear
        last = conn.execute("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        prev = last.hash if last else GENESIS
        conn.execute(
            "INSERT INTO audit_events (stream_id, ts_ms, service, action, outcome, actor, target, ip, detail,"
            " prev_hash, hash) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (stream_id) DO NOTHING",            # redelivered events are stored once
            (msg_id, int(event["ts_ms"]), *(event[f] for f in FIELDS[1:]), prev, chain_hash(prev, event)))
    rds.xack(AUDIT_STREAM, GROUP, msg_id)
    rds.xdel(AUDIT_STREAM, msg_id)


def ensure_group() -> None:
    try:
        rds.xgroup_create(AUDIT_STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def consume(stop: threading.Event) -> None:
    group_ready = False
    while not stop.is_set():
        try:
            if not group_ready:              # inside the retry loop: Redis may not be up yet at startup
                ensure_group()
                group_ready = True
            # Reclaim events another replica took but never acknowledged (e.g. it crashed).
            _, batch, _ = rds.xautoclaim(AUDIT_STREAM, GROUP, POD, min_idle_time=60_000, count=100)
            if not batch:
                batch = [m for _, msgs in rds.xreadgroup(GROUP, POD, {AUDIT_STREAM: ">"}, count=100, block=2000)
                         for m in msgs]
            for msg_id, event in batch:
                store(msg_id, event)
        except Exception:
            log.exception("audit consumer error; retrying")
            group_ready = False                 # re-check the group too (e.g. Redis came back empty)
            time.sleep(2)


app = create_app(worker=consume)


@app.get("/api/audit/events")
def events(s: dict = Depends(READER),
           action: Annotated[str, Query(pattern=r"^[a-z_]{0,32}$")] = "",
           page: Annotated[int, Query(ge=1, le=10_000)] = 1):
    with db.connection() as conn:
        rows = conn.execute(
            "SELECT id, ts_ms, service, action, outcome, actor, target, ip, detail FROM audit_events"
            " WHERE %s = '' OR action = %s ORDER BY id DESC LIMIT 51 OFFSET %s",
            (action, action, (page - 1) * 50)).fetchall()
    return {"events": [r._asdict() for r in rows[:50]], "has_more": len(rows) > 50,
            "served_by": {"service": "audit", "version": VERSION, "pod": POD}}


@app.get("/api/audit/stats")
def stats(s: dict = Depends(READER)):
    since = int(time.time() * 1000) - 86_400_000
    with db.connection() as conn:
        counts = conn.execute("SELECT action, count(*) AS n FROM audit_events WHERE ts_ms >= %s"
                              " GROUP BY action", (since,)).fetchall()
        top_ips = conn.execute("SELECT ip, count(*) AS n FROM audit_events WHERE ts_ms >= %s"
                               " AND action IN ('login_failed', 'login_blocked') GROUP BY ip"
                               " ORDER BY n DESC LIMIT 5", (since,)).fetchall()
    return {"last_24h": {r.action: r.n for r in counts}, "top_failing_ips": [r._asdict() for r in top_ips]}


@app.get("/api/audit/verify")
def verify(s: dict = Depends(READER)):
    prev, checked = GENESIS, 0
    with db.connection() as conn, conn.cursor(name="chain") as cur:   # server-side cursor: constant memory
        cur.execute("SELECT id, prev_hash, hash, " + ", ".join(FIELDS) + " FROM audit_events ORDER BY id")
        for row in cur:
            if row.prev_hash != prev or chain_hash(prev, row._asdict()) != row.hash:
                return {"valid": False, "broken_at_id": row.id, "checked": checked}
            prev, checked = row.hash, checked + 1
    return {"valid": True, "checked": checked}
