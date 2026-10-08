# 4-minute demo script (+2 min Q&A)

The time limit is strict and scaling failures cost marks, so rehearse it twice with a timer.

## Set up 10 minutes before marking

1. Cluster running, certificate **Active**, and `https://$DOMAIN` loads.
2. **Browser tab 1:** signed in as your admin (MFA done), on the **Security log** tab.
3. **Browser tab 2 (private window):** the sign-in page.
4. **Cloud Shell tab A:**
   - Run `export` for PROJECT_ID, REGION, ZONE, REPO, DOMAIN and SESSION (README 2.1, 2.5 and the load test section).
   - Run `alias k='kubectl -n portcullis'`.
   - Build and push `auth:v2` ahead of time (README rollout section). Only `set image` runs live.
5. **Cloud Shell tab B:** run `k get hpa auth -w`.
6. Create a user named `victim` (you'll lock it live).
7. Reset if you rehearsed: `k rollout undo deployment/auth` if v2 is still live, and `k scale deployment directory --replicas=2`.
8. Have the architecture diagram open.

## Script

| Time | Show | Say (short) |
|---|---|---|
| **0:00–0:30** | Title / diagram | "Stolen and guessed credentials are the most common way breaches start. Identity is the front door. Portcullis is an IAM platform that has to be both secure and always available, so I built it as microservices on GKE with security in every layer." |
| **0:30–1:05** | Architecture diagram | "Traffic hits Cloud Armor WAF first, then Google's HTTPS load balancer, then an nginx gateway. Behind it are three FastAPI microservices (auth, directory, audit) on PostgreSQL and Redis. Each service has its own least-privilege database role, so the directory service literally cannot read password hashes. Default-deny network policies allow only these arrows." |
| **1:05–1:10** | **Tab A:** start load: `~/go/bin/hey -z 150s -c 40 -q 2 -H "Cookie: __Host-session=$SESSION" https://$DOMAIN/api/auth/me` | "I'm starting about 80 requests a second now; we'll come back to it." |
| **1:10–1:55** | **Tab 2:** sign in as `victim` with a wrong password 6 times → "Too many failed attempts". **Tab 1:** refresh Security log: failures, lockout, attacker IP; **Users** tab: victim shows *locked* → **Unlock**. | "Brute force: after 5 failures the account locks. The attempt is counted before the password is checked, so parallel guessing can't race it. Unknown usernames lock the same way, so attackers can't tell which accounts exist. Passwords are Argon2id, MFA is TOTP with single-use codes, and admin tools need an MFA session." |
| **1:55–2:05** | **Tab A** (new shell line): `curl -s -o /dev/null -w "%{http_code}\n" "https://$DOMAIN/api/directory/users?q=1'%20OR%20'1'='1"` → **403** | "SQL injection is stopped at the edge by Cloud Armor's OWASP rules, before it reaches the cluster. Inside, every query is parameterised anyway." |
| **2:05–2:30** | **Tab B:** HPA replicas 2 → 3–4. `k get pods -o wide` | "Scalability: under load the autoscaler added auth replicas, spread across nodes. The load balancer spreads requests over them; the footer shows a different pod answering." |
| **2:30–2:50** | `k delete pod <one auth pod>` then refresh Tab 1 (still works) | "Reliability: I just killed a pod. Kubernetes replaces it, the other replicas carry traffic, and PodDisruptionBudgets keep a replica up even during node maintenance." |
| **2:50–3:25** | `k set image deployment/auth auth=$REPO/auth:v2` → `k rollout status deployment/auth` → footer shows **auth v2** → `k rollout undo deployment/auth` | "Rolling update: one pod at a time, new pods must pass readiness first, zero downtime. And if a release is bad, rollback is one command." |
| **3:25–3:45** | `k exec postgres-0 -- psql -U postgres -d iam -c "UPDATE audit_events SET actor='nobody' WHERE id=(SELECT max(id) FROM audit_events)"` → **Verify log integrity** → *TAMPERING DETECTED* | "Even someone with database access can't quietly rewrite history: each log row is hash-chained to the previous one." |
| **3:45–4:00** | Diagram / cost line | "All of this runs for about US$159 a month 24/7, or a few dollars for the hours I actually used. It's tested by a 62-check attack suite. Thank you." |

If you are running short of time, skip the tamper demo (3:25), not the cloud requirements.

## Likely Q&A, with short answers

- **Why JWT and not server sessions?** Stateless verification in every service with only the public key. But I also keep a server-side revocation list and a per-user generation counter, so logout and role changes take effect instantly, which plain JWTs can't do.
- **Why Ed25519 instead of HS256?** With HS256 every service holding the key could forge sessions. With Ed25519 only `auth` can sign; the others can only verify.
- **What if Redis goes down?** Logins fail closed: no session is issued without the brute-force counters. Revocations and queued audit events persist through restarts (AOF on a persistent disk).
- **What if the audit service is down?** Events wait in the Redis stream and are written when it returns. A crashed replica's unacknowledged events are reclaimed by another.
- **Single point of failure?** Stateless tiers are replicated and spread; Postgres/Redis are single replicas on persistent disks. In production I'd use Cloud SQL HA and Memorystore.
- **How do you get the real client IP?** Google's LB appends the client IP and its own IP to X-Forwarded-For. nginx takes the entry the LB wrote, so a client-supplied header can't spoof it.
- **How was the first admin created?** Only by a database superuser, on purpose. No API or service role can grant admin.
