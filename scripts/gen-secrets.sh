#!/bin/sh
# Generates every secret Portcullis needs into ./secrets (git-ignored).
# Run once from the project root:  sh scripts/gen-secrets.sh
set -eu
cd "$(dirname "$0")/.."
[ -e secrets ] && { echo "secrets/ already exists - delete it first to regenerate"; exit 1; }
mkdir secrets && cd secrets

# Ed25519 key pair: only auth holds the private key; other services can verify but never mint sessions.
openssl genpkey -algorithm ed25519 -out jwt_private.pem
openssl pkey -in jwt_private.pem -pubout -out jwt_public.pem

# 256-bit AES-GCM key that encrypts MFA secrets at rest.
openssl rand -hex 32 > mfa_key

# Random passwords: Postgres superuser, one DB role per service, one Redis user per service.
for name in db_admin db_auth db_directory db_audit redis_auth redis_directory redis_audit; do
  openssl rand -hex 24 > "${name}_password"
done

# Redis ACLs store only SHA-256 hashes of the passwords. Each service may touch only its own key
# patterns and a short list of commands (no KEYS, FLUSHALL, CONFIG, EVAL, ...).
sha() { printf %s "$(cat "$1")" | openssl dgst -sha256 -r | cut -d' ' -f1; }
cat > redis_acl <<EOF
user default off
user auth on #$(sha redis_auth_password) resetchannels ~fail:* ~totp:* ~revoked:* ~gen:* ~audit:events -@all +ping +get +set +incrby +decrby +del +expire +mget +xadd +multi +exec
user directory on #$(sha redis_directory_password) resetchannels ~fail:* ~revoked:* ~gen:* ~audit:events -@all +ping +mget +del +incrby +xadd +multi +exec
user audit on #$(sha redis_audit_password) resetchannels ~revoked:* ~gen:* ~audit:events -@all +ping +mget +xgroup|create +xreadgroup +xautoclaim +xack +xdel
EOF

# Readable by the non-root container users (files are mounted read-only).
chmod 644 ./*
echo "Secrets written to ./secrets"
