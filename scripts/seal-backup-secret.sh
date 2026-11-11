#!/usr/bin/env bash
# Prompts for the R2 and restic values and writes k3s/apps/backup/sealed-secret.yaml.
# Nothing is echoed or written in the clear; only the cluster's sealed-secrets
# controller can decrypt the result, so the output file is safe to commit.
#
#   KUBECONFIG=~/.kube/k3s-argocd-config scripts/seal-backup-secret.sh
set -euo pipefail

out="$(cd "$(dirname "$0")/.." && pwd)/k3s/apps/backup/sealed-secret.yaml"

read -r -p "Cloudflare account ID: " account
read -r -p "R2 bucket name: " bucket
read -r -s -p "R2 access key ID: " key; echo
read -r -s -p "R2 secret access key: " secret; echo
read -r -s -p "restic password (keep a copy outside the cluster): " pass; echo
read -r -s -p "restic password again: " pass2; echo
[ "$pass" = "$pass2" ] || { echo "restic passwords differ" >&2; exit 1; }
for v in account bucket key secret pass; do
  [ -n "${!v}" ] || { echo "$v is empty" >&2; exit 1; }
done

kubectl create secret generic backup-secrets -n capm --dry-run=client -o yaml \
  --from-literal=RESTIC_REPOSITORY="s3:https://${account}.r2.cloudflarestorage.com/${bucket}" \
  --from-literal=RESTIC_PASSWORD="$pass" \
  --from-literal=AWS_ACCESS_KEY_ID="$key" \
  --from-literal=AWS_SECRET_ACCESS_KEY="$secret" \
| kubeseal --controller-namespace kube-system --controller-name sealed-secrets-controller -o yaml > "$out"

echo "wrote $out"
