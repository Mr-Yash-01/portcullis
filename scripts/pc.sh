#!/bin/bash
# Portcullis helper: one command per demo/ops task.  Usage: ~/pc.sh <command>   (~/pc.sh help)
set -uo pipefail

export PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
export REGION=australia-southeast1 ZONE=australia-southeast1-a
export REPO=$REGION-docker.pkg.dev/$PROJECT_ID/portcullis
APP=~/portcullis
K="kubectl -n portcullis"
COOKIE=~/.pc_cookie
LOAD_USER=loadtest LOAD_PASS="amber kettle orbit 2026"

domain() { echo "$(gcloud compute addresses describe portcullis-ip --global --format='value(address)' | tr . -).sslip.io"; }

session() {   # sign in the load-test user (registers it first if needed); prints the session token
  local d=$(domain)
  curl -s -o /dev/null -X POST https://$d/api/auth/register -H 'Content-Type: application/json' \
    -d "{\"username\":\"$LOAD_USER\",\"password\":\"$LOAD_PASS\"}"
  curl -s -o /dev/null -c $COOKIE -X POST https://$d/api/auth/login -H 'Content-Type: application/json' \
    -d "{\"username\":\"$LOAD_USER\",\"password\":\"$LOAD_PASS\"}"
  awk '/__Host-session/ {print $7}' $COOKIE
}

case "${1:-help}" in
  status)    # pods (with node), autoscalers, nodes
    $K get pods -o wide; echo; $K get hpa; echo; kubectl get nodes ;;

  url)       echo "https://$(domain)" ;;

  check)     # security checks against the live site
    d=$(domain)
    echo "== Security headers"; curl -sI https://$d | grep -iE 'content-security|strict-transport|x-frame|referrer'
    echo "== SQL injection at the edge (expect 403):"; curl -s -o /dev/null -w "%{http_code}\n" "https://$d/api/directory/users?q=1'%20OR%20'1'='1"
    echo "== HTTP -> HTTPS redirect (expect 301):"; curl -s -o /dev/null -w "%{http_code}\n" http://$d/ ;;

  lb)        # 8 requests: watch different auth pods answer
    d=$(domain); s=$(session)
    for i in $(seq 8); do curl -s -b "__Host-session=$s" https://$d/api/auth/me | grep -o '"pod":"[^"]*"'; done ;;

  heal)      # kill one auth pod, show it being replaced
    p=$($K get pod -l app=auth -o name | head -1)
    $K delete $p; sleep 3; $K get pods -l app=auth ;;

  load)      # load test for N seconds (default 180) at ~45 req/s, under the per-IP limits
    hey="$(go env GOPATH | cut -d: -f1)/bin/hey"   # GOPATH can list several dirs; go install uses the first
    [ -x "$hey" ] || { echo "Installing hey..."; go install github.com/rakyll/hey@latest; }
    "$hey" -z "${2:-180}s" -c 45 -q 1 -H "Cookie: __Host-session=$(session)" https://$(domain)/api/auth/me ;;

  watch)     # watch the auth autoscaler (run in a 2nd tab during 'load')
    $K get hpa auth -w ;;

  build-v2)  # build auth:v2 in Cloud Build (do this BEFORE the demo, ~2 min)
    cat > /tmp/v2.yaml <<EOF
steps:
- name: gcr.io/cloud-builders/docker
  args: ['build', '--build-arg', 'SERVICE=auth', '--build-arg', 'VERSION=v2', '-t', '$REPO/auth:v2', 'services/']
images: ['$REPO/auth:v2']
EOF
    (cd $APP && gcloud builds submit --config /tmp/v2.yaml .) ;;

  update)    # zero-downtime rolling update to auth:v2
    $K set image deployment/auth auth=$REPO/auth:v2
    $K annotate deployment/auth kubernetes.io/change-cause="v2 release" --overwrite
    $K rollout status deployment/auth ;;

  rollback)  # back to the previous version
    $K rollout history deployment/auth; $K rollout undo deployment/auth; $K rollout status deployment/auth ;;

  tamper)    # edit the newest audit row directly in the DB; then press "Verify log integrity" in the UI
    $K exec postgres-0 -- psql -U postgres -d iam -c "UPDATE audit_events SET actor='nobody' WHERE id=(SELECT max(id) FROM audit_events)" ;;

  admin)     # promote a user to admin:  ~/pc.sh admin yash
    $K exec postgres-0 -- psql -U postgres -d iam -c "UPDATE users SET role='admin' WHERE username='${2:?give a username}'" ;;

  pause)     # stop the 3 nodes to save credit (data is kept)
    gcloud container clusters update portcullis --zone $ZONE --node-pool default-pool --no-enable-autoscaling
    gcloud container clusters resize portcullis --zone $ZONE --node-pool default-pool --num-nodes 0 --quiet ;;

  resume)    # bring the nodes back (~3 min until pods are Running)
    gcloud container clusters resize portcullis --zone $ZONE --node-pool default-pool --num-nodes 3 --quiet
    gcloud container clusters update portcullis --zone $ZONE --node-pool default-pool --enable-autoscaling --min-nodes 3 --max-nodes 4
    gcloud container clusters get-credentials portcullis --zone $ZONE ;;

  *) grep -E '^  [a-z0-9-]+\)' "$0" | sed 's/)//' ;;
esac
