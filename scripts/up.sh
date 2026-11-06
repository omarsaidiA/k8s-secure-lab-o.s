#!/usr/bin/env bash
# Build the whole lab: cluster, Kyverno and its policies, images, secrets and workloads.
# Safe to run again: existing secrets, images and the cluster itself are reused.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=secure-lab
NAMESPACE=petclinic
KYVERNO_VERSION=v1.19.2
# SHA-256 of the release's install.yaml: a tampered download is refused
KYVERNO_SHA256=4f785937dc7fe49a0731108b15def1538923c73d9236255bc69d94d498037969
PETCLINIC_REPO=${PETCLINIC_REPO:-https://github.com/omarsaidiA/Omar-Petclinic.git}
PETCLINIC_REF=9ec05d6d25235b9adfe100b62aeb915cae8cfa62
# Must match the image fields in manifests/
PETCLINIC_IMAGE=lab.local/omar-petclinic:${PETCLINIC_REF:0:7}
HEADERCHECK_IMAGE=lab.local/headercheck:f835ea5

step() { printf '\n==> %s\n' "$*"; }

step "Secrets encryption key"
if [ ! -f kind/encryption-config.yaml ]; then
  (
    umask 077
    cat > kind/encryption-config.yaml <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: [secrets]
    providers:
      # secretbox: authenticated encryption (XSalsa20 and Poly1305); new writes use the first provider
      - secretbox:
          keys:
            - name: key1
              secret: $(head -c 32 /dev/urandom | base64)
      # identity: Secrets written before encryption was enabled can still be read
      - identity: {}
EOF
  )
  echo "generated kind/encryption-config.yaml (git-ignored)"
fi

step "Cluster"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --config kind/cluster.yaml --wait 180s
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

step "Kyverno $KYVERNO_VERSION"
mkdir -p .cache
curl -fsSLo .cache/kyverno-install.yaml \
  "https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION}/install.yaml"
echo "$KYVERNO_SHA256  .cache/kyverno-install.yaml" | sha256sum -c --quiet
kubectl apply --server-side --force-conflicts -f .cache/kyverno-install.yaml >/dev/null
kubectl -n kyverno rollout status deployment --timeout=300s
# The admission webhook can still refuse connections for a few seconds after the rollout
for attempt in $(seq 1 30); do
  kubectl apply -f policies/ 2>/dev/null && break
  if [ "$attempt" -eq 30 ]; then kubectl apply -f policies/; fi
  sleep 5
done
kubectl wait --for=jsonpath='{.status.conditionStatus.ready}'=true validatingpolicies --all --timeout=120s

step "Images"
if ! docker image inspect "$PETCLINIC_IMAGE" >/dev/null 2>&1; then
  src=.cache/omar-petclinic
  [ -d "$src/.git" ] || git clone --quiet "$PETCLINIC_REPO" "$src"
  git -C "$src" fetch --quiet origin "$PETCLINIC_REF"
  git -C "$src" -c advice.detachedHead=false checkout --quiet "$PETCLINIC_REF"
  docker build -t "$PETCLINIC_IMAGE" "$src"
fi
docker image inspect "$HEADERCHECK_IMAGE" >/dev/null 2>&1 \
  || docker build -t "$HEADERCHECK_IMAGE" images/headercheck
kind load docker-image --name "$CLUSTER" "$PETCLINIC_IMAGE" "$HEADERCHECK_IMAGE"

step "Namespace and secrets"
kubectl apply -f manifests/namespace.yaml
create_secret() {
  if kubectl -n "$NAMESPACE" get secret "$1" >/dev/null 2>&1; then
    echo "secret/$1 already exists (kept: PostgreSQL only reads its password at first start)"
    return
  fi
  # Through a private temporary file: a --from-literal value would show up in the process list
  local file
  file=$(mktemp)
  chmod 600 "$file"
  # Strip \r too: openssl on Windows (Git Bash) ends lines with CRLF. PostgreSQL drops the \r
  # when it stores the password, Java sends it: authentication would fail.
  openssl rand -hex 24 | tr -d '\r\n' > "$file"
  kubectl -n "$NAMESPACE" create secret generic "$1" --from-file=password="$file"
  rm -f "$file"
}
create_secret postgres-credentials
create_secret keycloak-admin

step "Workloads"
kubectl apply -k manifests
kubectl -n "$NAMESPACE" rollout status statefulset/postgres --timeout=300s
kubectl -n "$NAMESPACE" rollout status deployment/keycloak --timeout=600s
kubectl -n "$NAMESPACE" rollout status deployment/petclinic-api --timeout=600s

step "Ready. Run scripts/verify.sh to test every security control."
