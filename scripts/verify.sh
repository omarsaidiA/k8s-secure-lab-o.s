#!/usr/bin/env bash
# Prove that every security control works, instead of trusting that it is configured.
# Rejection tests use server-side dry runs: requests go through the full admission chain
# (Pod Security, Kyverno) but nothing is created.
set -euo pipefail
cd "$(dirname "$0")/.."

NS=petclinic
PROBE_IMAGE=lab.local/headercheck:f835ea5
failures=0

pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; failures=$((failures + 1)); }
section() { printf '\n%s\n' "$*"; }

# expect_denied DESCRIPTION EXPECTED_TEXT < manifest
expect_denied() {
  local out
  if out=$(kubectl apply --dry-run=server -f - 2>&1); then
    fail "$1 (it was accepted)"
  elif grep -qF -- "$2" <<<"$out"; then
    pass "$1"
  else
    fail "$1 (denied for another reason: $out)"
  fi
}

# A pod that satisfies Pod Security "restricted" and every Kyverno policy; tests change one thing.
# pod_manifest NAME IMAGE [EXTRA_POD_SPEC_YAML] [CONTAINER_SECURITY_YAML]
pod_manifest() {
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: $NS
spec:
  restartPolicy: Never
  automountServiceAccountToken: ${AUTOMOUNT:-false}
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: test
      image: $2
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: [ALL] }
${3:-}
      resources:
        requests: { cpu: 10m, memory: 32Mi }
        limits: { memory: 64Mi }
EOF
}

section "1. Workloads are running"
for app in postgres keycloak petclinic-api; do
  if kubectl -n "$NS" wait --for=condition=Ready pod -l "app.kubernetes.io/name=$app" --timeout=60s >/dev/null; then
    pass "$app is ready"
  else
    fail "$app is not ready"
  fi
done

section "2. Secrets are encrypted at rest in etcd"
etcd_pod=$(kubectl -n kube-system get pod -l component=etcd -o jsonpath='{.items[0].metadata.name}')
# MSYS_NO_PATHCONV: stops Git Bash on Windows from rewriting /etc/... into Windows paths
stored=$(MSYS_NO_PATHCONV=1 kubectl -n kube-system exec "$etcd_pod" -- etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get "/registry/secrets/$NS/postgres-credentials" --print-value-only | head -c 26 | tr -d '\0')
if [ "$stored" = "k8s:enc:secretbox:v1:key1:" ]; then
  pass "postgres-credentials is stored encrypted (prefix: $stored)"
else
  fail "postgres-credentials is not encrypted in etcd (starts with: $stored)"
fi

section "3. Pod Security Admission (restricted)"
pod_manifest psa-privileged "$PROBE_IMAGE" | sed 's/allowPrivilegeEscalation: false/privileged: true/' \
  | expect_denied "a privileged container is rejected" "violates PodSecurity"
pod_manifest psa-root "$PROBE_IMAGE" | sed 's/runAsUser: 10001/runAsUser: 0/' \
  | expect_denied "a container running as root is rejected" "violates PodSecurity"

section "4. Kyverno admission policies"
pod_manifest kv-latest lab.local/headercheck:latest \
  | expect_denied "an image tagged :latest is rejected" "never ':latest'"
pod_manifest kv-registry docker.io/nginx:1.29 \
  | expect_denied "an image from an unknown registry is rejected" "allowed source"
pod_manifest kv-writable "$PROBE_IMAGE" | sed 's/readOnlyRootFilesystem: true/readOnlyRootFilesystem: false/' \
  | expect_denied "a writable root filesystem is rejected" "readOnlyRootFilesystem"
pod_manifest kv-limits "$PROBE_IMAGE" | sed '/limits:/d' \
  | expect_denied "a container without memory limit is rejected" "memory limit"
AUTOMOUNT=true pod_manifest kv-token "$PROBE_IMAGE" \
  | expect_denied "a mounted Kubernetes API token is rejected" "automountServiceAccountToken"
kubectl create deployment kv-deploy-latest --image=lab.local/headercheck:latest -n "$NS" \
  --dry-run=client -o yaml | expect_denied "a Deployment using :latest is rejected too (autogen)" "never ':latest'"
cat <<EOF | expect_denied "a namespace without Pod Security is rejected" "pod-security.kubernetes.io/enforce"
apiVersion: v1
kind: Namespace
metadata:
  name: kv-unprotected
EOF

section "5. Network policies (default deny)"
# Python is already in the headercheck image, so no extra image has to be allowed for this test.
# A name that resolves but cannot be connected to proves that DNS is allowed and TCP is dropped.
probe_command='      command:
        - /usr/local/bin/python
        - -c
        - |
          import socket
          for host, port in (("postgres", 5432), ("petclinic-api", 9966), ("keycloak", 8080)):
              try:
                  address = socket.gethostbyname(host)
              except OSError:
                  print(f"{host}:{port} no-dns")
                  continue
              try:
                  socket.create_connection((address, port), timeout=3).close()
                  print(f"{host}:{port} open")
              except OSError:
                  print(f"{host}:{port} blocked")'
kubectl -n "$NS" delete pod netpol-probe --ignore-not-found >/dev/null
pod_manifest netpol-probe "$PROBE_IMAGE" "$probe_command" | kubectl apply -f - >/dev/null
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/netpol-probe --timeout=90s >/dev/null || true
probe_out=$(kubectl -n "$NS" logs netpol-probe 2>&1 || true)
kubectl -n "$NS" delete pod netpol-probe --wait=false >/dev/null
for target in postgres:5432 petclinic-api:9966 keycloak:8080; do
  if grep -qx "$target blocked" <<<"$probe_out"; then
    pass "an unrelated pod cannot reach $target (DNS works, the connection is dropped)"
  else
    fail "an unrelated pod can reach $target or the probe failed: $probe_out"
  fi
done

section "6. headercheck audits the API from inside the cluster (allowed flow)"
job="headercheck-verify-$(date +%s)"
kubectl -n "$NS" create job "$job" --from=cronjob/headercheck >/dev/null
if kubectl -n "$NS" wait --for=condition=Complete "job/$job" --timeout=120s >/dev/null; then
  pass "headercheck job succeeded (no finding at or above medium)"
else
  fail "headercheck job failed"
fi
kubectl -n "$NS" logs "job/$job" | sed 's/^/        /'

section "7. Authentication and authorization end to end"
kubectl -n "$NS" port-forward svc/keycloak 8080:8080 >/dev/null 2>&1 &
pf_keycloak=$!
kubectl -n "$NS" port-forward svc/petclinic-api 9966:9966 >/dev/null 2>&1 &
pf_api=$!
trap 'kill $pf_keycloak $pf_api 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
  curl -s -o /dev/null http://localhost:8080/realms/omar-petclinic \
    && curl -s -o /dev/null http://localhost:9966/petclinic/actuator/health && break
  sleep 1
done

token() {
  curl -s -X POST http://localhost:8080/realms/omar-petclinic/protocol/openid-connect/token \
    -d grant_type=password -d client_id=omar-petclinic-api \
    -d username="$1" --data-urlencode "password=$2" \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
# expect_status DESCRIPTION EXPECTED_CODE CURL_ARGS...
expect_status() {
  local description=$1 expected=$2 code
  shift 2
  code=$(curl -s -o /dev/null -w '%{http_code}' "$@")
  if [ "$code" = "$expected" ]; then pass "$description ($code)"; else fail "$description: got $code, expected $expected"; fi
}

api=http://localhost:9966/petclinic/api
vet=$(token vet 'Vet-DevOnly-2026!')
owner=$(token owner 'Owner-DevOnly-2026!')
expect_status "no token: access denied" 401 "$api/owners"
expect_status "VET reads the owners" 200 -H "Authorization: Bearer $vet" "$api/owners"
expect_status "VET cannot delete a pet" 403 -X DELETE -H "Authorization: Bearer $vet" "$api/pets/1"
expect_status "OWNER reads their own record" 200 -H "Authorization: Bearer $owner" "$api/owners/1"
expect_status "OWNER cannot read another owner (BOLA)" 403 -H "Authorization: Bearer $owner" "$api/owners/2"

printf '\n'
if [ "$failures" -eq 0 ]; then
  echo "All security controls verified."
else
  echo "$failures check(s) failed."
  exit 1
fi
