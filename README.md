# Portcullis: a secure, scalable Identity & Access Management platform on GKE

INFS3208 Individual Project (Type I) · Yash Vadukiya (49788727)

Portcullis is a small IAM platform:
- user registration and sign-in with TOTP multi-factor authentication
- brute-force lockout
- role-based access control (user / auditor / admin)
- admin user management
- a tamper-evident security audit log

It runs as microservices on Google Kubernetes Engine behind Cloud Armor and an HTTPS load balancer.

```
 Browser ──HTTPS──▶ Cloud Armor WAF ─▶ Global HTTPS Load Balancer (managed cert, TLS 1.2+)
                                              │  (container-native, straight to pod IPs)
                                     ┌────────▼────────┐
                                     │ gateway (nginx) │  UI · security headers · rate limits   HPA 2–4
                                     └──┬──────┬─────┬─┘
                    /api/auth      ┌────▼─┐ ┌──▼──────┐ ┌▼─────┐   FastAPI microservices,
                    /api/directory │ auth │ │directory│ │audit │   HPA 2–8 / 2–4 / 2–4
                    /api/audit     └──┬─┬─┘ └──┬───┬──┘ └┬───┬─┘
                                      │ └──────┼───┼─────┼─┐ │
                               ┌──────▼────────▼┐ ┌▼─────▼─▼─▼┐
                               │ PostgreSQL     │ │ Redis      │  lockouts, revocations,
                               │ users + audit  │ │ (ACL users)│  audit event stream
                               └────────────────┘ └────────────┘
```

| Service | Job | Data access (least privilege) |
|---|---|---|
| `gateway` | Serves the UI and proxies `/api/*`; CSP, HSTS, per-IP rate limits | none |
| `auth` | Register, sign in, MFA, sessions, sign out | `users` (credential columns), signs session tokens |
| `directory` | Admin: list users, change role, enable/disable, unlock | `users` profile columns only, **cannot read password hashes or MFA secrets** |
| `audit` | Consumes events, stores a SHA-256 hash chain, stats, integrity check | `audit_events` INSERT/SELECT only (append-only) |

Security design and the full threat model are in [SECURITY.md](SECURITY.md). The 4-minute demo script is in [DEMO.md](DEMO.md).

## Repository layout

```
services/               Python microservices (one Dockerfile, built per service)
  common/sec.py         shared security code: session checks, CSRF, audit publishing, safe errors
  auth/ directory/ audit/
  requirements.txt      every dependency pinned with SHA-256 hashes
gateway/                nginx config + HTML/CSS/JS UI
db/init.sh              schema + one least-privilege Postgres role per service
redis/redis.conf        Redis config (ACL file, durability, no eviction)
scripts/gen-secrets.sh  generates keys/passwords into ./secrets (never committed)
k8s/                    Kubernetes manifests (namespace, data stores, services, gateway/ingress, network policies)
tests/security_test.py  end-to-end functional + attack test suite (62 checks)
docker-compose.yml      local development stack
```

---

## 1. Run locally (optional, before spending cloud credit)

Requires Docker with Compose, and OpenSSL 3 (Cloud Shell and Linux have it).

```bash
# Generate every key and password into ./secrets (the Ed25519 signing key pair, AES key, DB and Redis passwords)
sh scripts/gen-secrets.sh

# Build the 4 images and start all 6 containers; the UI is then at http://localhost:8080 (use Chrome or Edge)
docker compose up --build -d

# Promote your account to admin. On purpose, no API can do this; it needs direct DB superuser access.
#   -T: no TTY; -U postgres: superuser; -d iam: the app database; -c: run one SQL statement
docker compose exec -T postgres psql -U postgres -d iam -c "UPDATE users SET role='admin' WHERE username='yash'"

# Run the 62-check functional + attack test suite against the local stack
#   BASE: gateway URL; PSQL: how the tests run SQL as superuser (to create an admin and to simulate tampering)
BASE=http://localhost:8080 PSQL='docker compose exec -T postgres psql -U postgres -d iam -tAc' python3 tests/security_test.py

# Stop everything and delete the local volumes (-v)
docker compose down -v
```

---

## 2. Deploy to Google Cloud (run in Cloud Shell)

Upload the project zip to Cloud Shell (⋮ → Upload), then `unzip portcullis.zip && cd portcullis`.

### 2.1 Variables and APIs

```bash
# Your GCP project ID (check it carefully)
export PROJECT_ID=$(gcloud config get-value project)
# Sydney: the closest region to Brisbane, for low latency
export REGION=australia-southeast1
# A zonal cluster: GKE's free tier covers the management fee of one zonal cluster
export ZONE=australia-southeast1-a
# Where the container images are pushed
export REPO=$REGION-docker.pkg.dev/$PROJECT_ID/portcullis

# Enable the APIs we use: GKE, Artifact Registry, Compute Engine (load balancer, Cloud Armor, IPs)
gcloud services enable container.googleapis.com artifactregistry.googleapis.com compute.googleapis.com
```

### 2.2 Least-privilege node identity

The default Compute Engine service account has the broad Editor role. Nodes only need to write logs and metrics and pull images, so we give them a dedicated account with exactly that.

```bash
# Create a dedicated service account for the cluster nodes
gcloud iam service-accounts create portcullis-nodes --display-name "Portcullis GKE nodes"
export NODE_SA=portcullis-nodes@$PROJECT_ID.iam.gserviceaccount.com

# Grant only GKE's minimal node role (write logs and metrics). Image access is granted on our one repository in 2.4.
gcloud projects add-iam-policy-binding $PROJECT_ID --member "serviceAccount:$NODE_SA" \
  --role roles/container.defaultNodeServiceAccount --condition=None
```

### 2.3 Create the GKE cluster (about 5–8 minutes)

The flags:
- `--num-nodes 3 --machine-type e2-medium`: 3 nodes (2 vCPU, 4 GB each), so replicas can spread across machines.
- `--disk-type pd-standard --disk-size 30`: small, cheap boot disks (the default is 100 GB pd-balanced).
- `--enable-dataplane-v2`: eBPF networking that **enforces NetworkPolicies**. It can only be set when the cluster is created.
- `--service-account`: nodes run as the least-privilege account above.
- `--shielded-secure-boot --shielded-integrity-monitoring`: verified boot, so rootkits and tampered kernels are detected.
- `--enable-autoscaling --min-nodes 3 --max-nodes 4`: adds a node if scaled-out pods no longer fit.
- `--release-channel regular`: automatic security patching of the control plane and nodes.

```bash
gcloud container clusters create portcullis \
  --zone $ZONE \
  --num-nodes 3 --machine-type e2-medium \
  --disk-type pd-standard --disk-size 30 \
  --enable-dataplane-v2 \
  --service-account $NODE_SA \
  --shielded-secure-boot --shielded-integrity-monitoring \
  --enable-autoscaling --min-nodes 3 --max-nodes 4 \
  --release-channel regular

# Point kubectl at the new cluster
gcloud container clusters get-credentials portcullis --zone $ZONE
```

### 2.4 Build and push the images

```bash
# Create a private Docker repository in Artifact Registry, in the same region as the cluster
gcloud artifacts repositories create portcullis --repository-format=docker --location=$REGION

# Nodes may pull (read) images from this repository only, not from every repository in the project
gcloud artifacts repositories add-iam-policy-binding portcullis --location=$REGION \
  --member "serviceAccount:$NODE_SA" --role roles/artifactregistry.reader

# Let Docker in Cloud Shell push to that registry using your gcloud login
gcloud auth configure-docker $REGION-docker.pkg.dev --quiet

# Build each Python microservice from the shared Dockerfile and push it.
#   SERVICE: which service's code goes into the image; VERSION: shown in the UI footer (used in the rollout demo)
for s in auth directory audit; do
  docker build --build-arg SERVICE=$s --build-arg VERSION=v1 -t $REPO/$s:v1 services/
  docker push $REPO/$s:v1
done

# Build and push the nginx gateway (UI + reverse proxy)
docker build -t $REPO/gateway:v1 gateway/ && docker push $REPO/gateway:v1
```

### 2.5 Edge security: static IP, HTTPS policy, Cloud Armor WAF

```bash
# Reserve a global static IP for the load balancer, so the address (and the certificate) never change
gcloud compute addresses create portcullis-ip --global
export IP=$(gcloud compute addresses describe portcullis-ip --global --format='value(address)')

# Free DNS name for that IP: sslip.io resolves 34-1-2-3.sslip.io to 34.1.2.3. Google's managed certificate needs a domain.
export DOMAIN=$(echo $IP | tr . -).sslip.io && echo "App URL: https://$DOMAIN"

# TLS policy: only TLS 1.2+ with the MODERN cipher profile (no legacy, weak ciphers)
gcloud compute ssl-policies create portcullis-tls --profile MODERN --min-tls-version 1.2

# Cloud Armor security policy attached to the load balancer (via BackendConfig in k8s/30-gateway.yaml)
gcloud compute security-policies create portcullis-waf --description "Portcullis edge WAF"

# Parse JSON request bodies, so WAF rules inspect JSON fields properly instead of raw text (fewer false positives)
gcloud compute security-policies update portcullis-waf --json-parsing=STANDARD

# OWASP Core Rule Set 4.22 at sensitivity 1 (fewest false positives). Each rule returns 403 on a match. The attacks blocked:
#   SQL injection, cross-site scripting, local file inclusion, remote code execution, vulnerability scanners, HTTP protocol attacks
priority=1000
for rule in sqli xss lfi rce scannerdetection protocolattack; do
  gcloud compute security-policies rules create $priority --security-policy portcullis-waf \
    --expression "evaluatePreconfiguredWaf('$rule-v422-stable', {'sensitivity': 1})" \
    --action deny-403 --description "OWASP CRS: $rule"
  priority=$((priority + 1))
done

# Per-IP flood protection, evaluated after the WAF rules:
#   more than 6000 requests in 60 s from one IP -> that IP gets HTTP 429 for 5 minutes
gcloud compute security-policies rules create 2000 --security-policy portcullis-waf \
  --src-ip-ranges "*" --action rate-based-ban \
  --rate-limit-threshold-count 6000 --rate-limit-threshold-interval-sec 60 \
  --ban-duration-sec 300 --conform-action allow --exceed-action deny-429 --enforce-on-key IP
```

### 2.6 Secrets and configuration

Each pod receives **only** the secrets it needs. The private signing key exists only in `auth`.

```bash
# Create the namespace (it enforces the "restricted" Pod Security Standard)
kubectl apply -f k8s/00-namespace.yaml

# Generate all secrets into ./secrets
sh scripts/gen-secrets.sh

# auth: private + public signing keys, MFA encryption key, its own DB and Redis passwords
kubectl -n portcullis create secret generic auth-secrets \
  --from-file=secrets/jwt_private.pem --from-file=secrets/jwt_public.pem --from-file=secrets/mfa_key \
  --from-file=secrets/db_auth_password --from-file=secrets/redis_auth_password

# directory and audit: public key only (they can verify sessions but never create them), plus their own passwords
kubectl -n portcullis create secret generic directory-secrets \
  --from-file=secrets/jwt_public.pem --from-file=secrets/db_directory_password --from-file=secrets/redis_directory_password
kubectl -n portcullis create secret generic audit-secrets \
  --from-file=secrets/jwt_public.pem --from-file=secrets/db_audit_password --from-file=secrets/redis_audit_password

# postgres: superuser password + the 3 service passwords (used once by db/init.sh to create the roles)
kubectl -n portcullis create secret generic postgres-secrets \
  --from-file=secrets/db_admin_password --from-file=secrets/db_auth_password \
  --from-file=secrets/db_directory_password --from-file=secrets/db_audit_password

# redis: the ACL file (per-service users with hashed passwords and allowed commands)
kubectl -n portcullis create secret generic redis-secrets --from-file=secrets/redis_acl

# Non-secret config: the DB init script and the Redis config file
kubectl -n portcullis create configmap postgres-init --from-file=db/init.sh
kubectl -n portcullis create configmap redis-config --from-file=redis/redis.conf
```

### 2.7 Deploy

```bash
# Fill in the image registry and domain placeholders, then apply all manifests in order
#   (namespace, Postgres, Redis, the 3 services, gateway + ingress, network policies)
cat k8s/*.yaml | sed "s|IMAGE_REPO|$REPO|g; s|DOMAIN|$DOMAIN|g" | kubectl apply -f -

# Watch the pods start (Ctrl+C to stop watching). -o wide shows which node each pod is on.
kubectl -n portcullis get pods -o wide -w

# The HTTPS certificate is issued after DNS and the load balancer are live: 15–60 min.
# Wait until Status shows "Active".
kubectl -n portcullis get managedcertificate portcullis-cert -w
```

### 2.8 Create the first admin

1. Open `https://$DOMAIN` and create your account.
2. Promote it to admin. This is deliberately impossible through the API: no service's database role can change a role it doesn't own.

   ```bash
   # Run SQL as the Postgres superuser inside the database pod
   kubectl -n portcullis exec -it postgres-0 -- psql -U postgres -d iam -c "UPDATE users SET role='admin' WHERE username='yash'"
   ```

3. Sign in again and enable MFA under **My account**. The **Users** and **Security log** tabs unlock only for MFA-verified sessions.

---

## 3. Operating it (scaling, reliability, load balancing, rollout, rollback)

Shortcut: `scripts/pc.sh` wraps every command below (`bash scripts/pc.sh help`).

```bash
# Short alias: every command below targets the portcullis namespace
alias k='kubectl -n portcullis'

# Show pods with their node, the autoscalers, and live CPU/memory per pod
k get pods -o wide
k get hpa
k top pods
```

### Load test → autoscaling

```bash
# Install the 'hey' HTTP load generator (Cloud Shell has Go)
go install github.com/rakyll/hey@latest

# Create a normal test account and sign in. curl stores the session cookie in /tmp/cj.
#   -c: cookie jar file; -H: JSON body; -d: request body
curl -s -X POST https://$DOMAIN/api/auth/register -H 'Content-Type: application/json' -d '{"username":"loadtest","password":"amber kettle orbit 2026"}'
curl -s -c /tmp/cj -X POST https://$DOMAIN/api/auth/login -H 'Content-Type: application/json' -d '{"username":"loadtest","password":"amber kettle orbit 2026"}'
export SESSION=$(awk '/__Host-session/ {print $7}' /tmp/cj)

# 3 minutes of authenticated traffic at ~80 req/s (under the per-IP limits of nginx and Cloud Armor).
#   -z: duration; -c: concurrent workers; -q: requests/s per worker; -H: send the session cookie
~/go/bin/hey -z 180s -c 40 -q 2 -H "Cookie: __Host-session=$SESSION" https://$DOMAIN/api/auth/me

# In a second Cloud Shell tab: watch the auth HPA add replicas as CPU passes 50%,
# then remove them about 1 minute after the load stops
kubectl -n portcullis get hpa auth -w

# Manual scaling also works at any time, without downtime
k scale deployment directory --replicas=4
```

### Load balancing

```bash
# Each request is answered by a different auth pod (the UI footer also shows the serving pod)
for i in $(seq 8); do curl -s -b "__Host-session=$SESSION" https://$DOMAIN/api/auth/me | jq -r .served_by.pod; done
```

### Reliability (self-healing and node failure)

```bash
# Kill one auth pod: the Deployment replaces it, and the other replica keeps serving meanwhile
k delete pod $(k get pod -l app=auth -o name | head -1 | cut -d/ -f2)

# Simulate a node failure: pick a node that does NOT run postgres-0 or redis-0 (see 'k get pods -o wide').
#   drain: evicts its pods (PodDisruptionBudgets keep ≥1 replica of each service up) and blocks new ones
kubectl drain NODE_NAME --ignore-daemonsets --delete-emptydir-data
# Bring the node back into service
kubectl uncordon NODE_NAME
```

### Rolling update and rollback

```bash
# Build a v2 of auth (same code, VERSION=v2, shown in the UI footer)
docker build --build-arg SERVICE=auth --build-arg VERSION=v2 -t $REPO/auth:v2 services/ && docker push $REPO/auth:v2

# Roll it out: pods are replaced one at a time (maxSurge 1, maxUnavailable 0), so there is no downtime
k set image deployment/auth auth=$REPO/auth:v2
# Record why this revision exists (shown in rollout history)
k annotate deployment/auth kubernetes.io/change-cause="v2 release" --overwrite
# Follow the rollout until every pod is on v2
k rollout status deployment/auth

# List revisions, then roll back to the previous one (v1), also without downtime
k rollout history deployment/auth
k rollout undo deployment/auth
k rollout status deployment/auth
```

### Security checks to show

```bash
# Browser hardening headers on every response
curl -sI https://$DOMAIN | grep -iE 'content-security|strict-transport|x-frame|referrer'

# Cloud Armor blocks a SQL-injection attempt at the edge, before it reaches the cluster (expect 403)
curl -s -o /dev/null -w "%{http_code}\n" "https://$DOMAIN/api/directory/users?q=1'%20OR%20'1'='1"

# HTTP redirects to HTTPS (expect 301)
curl -s -o /dev/null -w "%{http_code}\n" http://$DOMAIN/

# Pod Security admission: a container running as root is rejected in this namespace
k run root-test --image=busybox:1.37 --restart=Never -- id

# Network policy: a pod outside the gateway cannot reach the auth API (expect a timeout)
kubectl run probe --rm -it --restart=Never --image=busybox:1.37 -- wget -qO- -T 3 http://auth.portcullis:8000/healthz

# Audit tamper detection: edit a log row directly in the DB, then press "Verify log integrity" in the UI
k exec postgres-0 -- psql -U postgres -d iam -c "UPDATE audit_events SET actor='nobody' WHERE id=(SELECT max(id) FROM audit_events)"
```

---

## 4. Clean up (stop all charges)

```bash
# Delete the cluster (nodes, its load balancer and its pods)
gcloud container clusters delete portcullis --zone $ZONE --quiet

# Cluster deletion does NOT delete the Postgres/Redis persistent disks: list them, then delete them
gcloud compute disks list --filter="name~pvc"
gcloud compute disks list --filter="name~pvc" --format="value(name,zone)" | while read n z; do gcloud compute disks delete $n --zone $z --quiet; done

# Release the static IP (it is billed while reserved), then remove the WAF and TLS policies and the images
gcloud compute addresses delete portcullis-ip --global --quiet
gcloud compute security-policies delete portcullis-waf --quiet
gcloud compute ssl-policies delete portcullis-tls --quiet
gcloud artifacts repositories delete portcullis --location=$REGION --quiet
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Browser shows a certificate error | The managed certificate isn't Active yet. Wait, and check with `k describe managedcertificate portcullis-cert`. |
| `502` from the load balancer for a few minutes after deploy | Normal while health checks pass for the first time. Check `k get pods`. |
| Ingress events mention `portcullis-waf` or `portcullis-tls` not found | Run section 2.5 first, then `k delete ingress portcullis` and re-apply. |
| Pod `CreateContainerConfigError` | A secret or configmap from 2.6 is missing: `k describe pod <name>`. |
| Need to re-run `db/init.sh` | It only runs on an empty volume: `k delete statefulset postgres && k delete pvc data-postgres-0`, then re-apply (this deletes all data). |
| Login works locally in Firefox only over HTTPS | `__Host-` Secure cookies on `http://localhost` work in Chrome/Edge; use those for local testing. |
