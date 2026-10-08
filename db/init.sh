#!/bin/sh
# Runs once, on first start of an empty Postgres volume (docker-entrypoint-initdb.d).
# Creates the schema plus one least-privilege role per microservice.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v auth_pw="$(cat /run/secrets/db_auth_password)" \
  -v directory_pw="$(cat /run/secrets/db_directory_password)" \
  -v audit_pw="$(cat /run/secrets/db_audit_password)" <<'SQL'
-- Nothing is granted by default; each service gets exactly what it needs.
REVOKE ALL ON DATABASE iam FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE TABLE users (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_.-]{3,32}$'),
  password_hash TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
  role          TEXT NOT NULL DEFAULT 'user'   CHECK (role IN ('user', 'auditor', 'admin')),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  mfa_secret    BYTEA,                         -- AES-256-GCM ciphertext, never plaintext
  mfa_enabled   BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at TIMESTAMPTZ
);

CREATE TABLE audit_events (
  id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  stream_id TEXT NOT NULL UNIQUE,              -- Redis stream id: makes redelivery idempotent
  ts_ms     BIGINT NOT NULL,
  service   TEXT NOT NULL,
  action    TEXT NOT NULL,
  outcome   TEXT NOT NULL,
  actor     TEXT NOT NULL DEFAULT '',
  target    TEXT NOT NULL DEFAULT '',
  ip        TEXT NOT NULL DEFAULT '',
  detail    TEXT NOT NULL DEFAULT '{}',
  prev_hash BYTEA NOT NULL,
  hash      BYTEA NOT NULL
);
CREATE INDEX audit_events_ts ON audit_events (ts_ms);
CREATE INDEX audit_events_action ON audit_events (action, id);

CREATE ROLE auth_svc      LOGIN PASSWORD :'auth_pw'      CONNECTION LIMIT 60;
CREATE ROLE directory_svc LOGIN PASSWORD :'directory_pw' CONNECTION LIMIT 60;
CREATE ROLE audit_svc     LOGIN PASSWORD :'audit_pw'     CONNECTION LIMIT 60;
GRANT CONNECT ON DATABASE iam TO auth_svc, directory_svc, audit_svc;
GRANT USAGE ON SCHEMA public TO auth_svc, directory_svc, audit_svc;

-- auth: credentials. It can create users but can never change a role (no admin self-promotion).
GRANT SELECT (id, username, password_hash, role, status, mfa_secret, mfa_enabled, created_at, last_login_at),
      INSERT (username, password_hash),
      UPDATE (password_hash, mfa_secret, mfa_enabled, last_login_at) ON users TO auth_svc;

-- directory: profile management. Column grants mean it cannot even read hashes or MFA secrets.
GRANT SELECT (id, username, role, status, mfa_enabled, created_at, last_login_at),
      UPDATE (role, status) ON users TO directory_svc;

-- audit: append-only. No UPDATE or DELETE, so history can't be rewritten through the app.
GRANT SELECT, INSERT ON audit_events TO audit_svc;

-- Cap runaway queries so one request can't exhaust the database.
ALTER ROLE auth_svc      SET statement_timeout = '5s';
ALTER ROLE directory_svc SET statement_timeout = '5s';
ALTER ROLE audit_svc     SET statement_timeout = '30s';
SQL
