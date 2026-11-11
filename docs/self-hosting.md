# Self-hosting the capm registry on k3s

How the public registry at `https://capm.masondrake.dev` is run, how to set it
up from nothing, and the manual procedures (restore, takedown, rollback) that
stand in for features capm v1 does not have. Read
[security-notes.md](security-notes.md) first; the public deployment section
there explains why the takedown runbook matters.

Every `kubectl` command below assumes:

```sh
export KUBECONFIG=~/.kube/k3s-argocd-config
```

## What runs where

```
visitor -> Cloudflare (TLS) -> tunnel connector -> Traefik :80 on 10.0.10.19
                                                    |-- /v1 -> Service backend:8080  (Deployment backend)
                                                    `-- /   -> Service frontend:3000 (Deployment frontend)
```

- Everything is in namespace `capm` on the single-node k3s cluster, deployed
  by one ArgoCD Application (`capm`, path `k3s/` of this repo, automated sync
  with prune and selfHeal).
- The backend is one replica with `strategy: Recreate`. SQLite allows one
  writer, so a rollout stops the old pod before starting the new one.
- All backend state is on PVC `capm-data` (`local-path`, mounted at `/data`):
  `capm.db` (SQLite, WAL mode) and `blobs/<sha256>`. The PVC is annotated
  `Prune=false,Delete=false`, so neither an ArgoCD prune nor deleting the
  Application removes it. `local-path` does not enforce the 5Gi request; the
  `CapmDataVolumeFilling` alert fires at 4Gi.
- CronJob `capm-backup` runs at 03:30 node time. It copies `capm.db` with
  SQLite's online backup, then `restic` stores that copy and `blobs/` in a
  Cloudflare R2 bucket, encrypted client side, keeping 7 daily and 4 weekly
  snapshots. Worst-case loss is everything published since the last run.
- Images are pinned in the manifests by full commit SHA. The CI, Release and
  Deploy workflows build them and commit `chore: deploy <sha>` to `main`.

## One-time setup

These steps cannot be done from the repo. `<...>` marks values you supply.

1. **GitHub OAuth app.** GitHub, Settings, Developer settings, OAuth Apps, New
   OAuth App. Tick **Enable Device Flow**. Any homepage and callback URL will
   do. Copy the Client ID (no secret is needed) into `GITHUB_CLIENT_ID` in
   `k3s/apps/backend/configmap.yaml`, commit and push.
2. **R2 bucket and token.** Create a Cloudflare R2 bucket and an API token
   scoped to that bucket with read and write access. Choose a restic password
   and keep a copy outside the cluster. Without it the backups cannot be read.
3. **Seal the backup secret.** Run this from the repo root. Replace the four
   placeholder values; the plaintext Secret is only piped, never written to
   disk.

   ```sh
   kubectl create secret generic backup-secrets -n capm --dry-run=client -o yaml \
     --from-literal=RESTIC_REPOSITORY='s3:https://<account-id>.r2.cloudflarestorage.com/<bucket>' \
     --from-literal=RESTIC_PASSWORD='<restic password>' \
     --from-literal=AWS_ACCESS_KEY_ID='<R2 access key id>' \
     --from-literal=AWS_SECRET_ACCESS_KEY='<R2 secret access key>' \
   | kubeseal --controller-namespace kube-system \
       --controller-name sealed-secrets-controller -o yaml > k3s/apps/backup/sealed-secret.yaml
   ```

   Commit and push `k3s/apps/backup/sealed-secret.yaml`. It is safe to commit;
   only the cluster's sealed-secrets controller can decrypt it.
4. **Images public.** After the first Release run, set the three GHCR packages
   (`capm/backend`, `capm/frontend`, `capm/backup`) to public so the cluster
   needs no pull secret.
5. **Apply the Application, once.**

   ```sh
   kubectl apply -f k3s/argocd/application.yaml
   kubectl -n argocd get application capm
   kubectl -n capm get pods
   kubectl -n capm get pvc capm-data
   ```

   Expect the Application `Synced` and `Healthy`, backend and frontend `1/1
   Running`, and the PVC `Bound`. From here on, changes reach the cluster by
   merging to `main`.
6. **Tunnel hostname.** In the Cloudflare dashboard add a public hostname to
   the existing tunnel: `capm.masondrake.dev` -> `http://10.0.10.19:80`. Check
   with `curl -s https://capm.masondrake.dev/v1/bundles`, which should return
   JSON.
7. **Cloudflare rate-limit rule** on `/v1/auth/*` and `PUT /v1/bundles/*`, as
   a second layer in front of the app's own limits. Thresholds are yours to
   tune.

### Client IP header

The backend rate-limits auth requests per client IP. With `TRUSTED_PROXY=true`
it uses the rightmost `X-Forwarded-For` entry, which behind Cloudflare, the
tunnel connector and Traefik may be the connector rather than the visitor,
putting everyone in one bucket. Check what actually arrives (a throwaway
`traefik/whoami` pod behind a temporary Ingress on a spare path) before
changing anything. If the rightmost `X-Forwarded-For` entry is not the
caller's public IP and `Cf-Connecting-Ip` is, add `CLIENT_IP_HEADER:
CF-Connecting-IP` to `k3s/apps/backend/configmap.yaml`, push, and restart the
backend (`kubectl -n capm rollout restart deploy/backend`; a ConfigMap change
alone does not restart pods). Read the trust caveat in
[security-notes.md](security-notes.md) before setting it.

## Pausing ArgoCD for maintenance

The restore and takedown procedures need the backend scaled to 0. The
Application has `selfHeal: true`, so ArgoCD would scale it back to 1 within
moments. Turn automated sync off for the duration, and back on afterwards.

```sh
# Pause: remove the automated sync policy from the live Application.
kubectl -n argocd patch application capm --type merge \
  -p '{"spec":{"syncPolicy":{"automated":null}}}'

# Resume (same values as k3s/argocd/application.yaml):
kubectl -n argocd patch application capm --type merge \
  -p '{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true,"allowEmpty":false}}}}'
```

Do not forget to resume. While paused, merges to `main` do not roll out.
Resuming syncs the Application, which restores the backend to the
`replicas: 1` in git.

## Maintenance pod

Restore and takedown both use a one-off pod built from the backup image (it has
`restic` and `sqlite3`). It mounts `capm-data` at `/data` and gets the
`backup-secrets` environment. Only start it after the backend is at 0 replicas:
`capm-data` is `ReadWriteOnce`, and SQLite must have a single writer.

First pick the image, using the tag currently in the CronJob:

```sh
IMG=$(kubectl -n capm get cronjob capm-backup \
  -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].image}')
echo "$IMG"
```

Then stop the backend and start the pod:

```sh
kubectl -n argocd patch application capm --type merge \
  -p '{"spec":{"syncPolicy":{"automated":null}}}'
kubectl -n capm scale deploy/backend --replicas=0
kubectl -n capm wait --for=delete pod -l app=backend --timeout=120s

kubectl -n capm apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: capm-maint
  namespace: capm
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
  containers:
    - name: maint
      image: ${IMG}
      command: ["sleep", "7200"]
      env:
        - name: RESTIC_CACHE_DIR
          value: /tmp/restic-cache
      envFrom:
        - secretRef:
            name: backup-secrets
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      volumeMounts:
        - { name: data, mountPath: /data }
        - { name: restore, mountPath: /restore }
        - { name: tmp, mountPath: /tmp }
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: capm-data
    - name: restore
      emptyDir: {}
    - name: tmp
      emptyDir: {}
EOF
kubectl -n capm wait --for=condition=Ready pod/capm-maint --timeout=120s
kubectl -n capm exec -it capm-maint -- sh
```

The pod runs as uid/gid 65532, so every file it creates under `/data` is owned
by the backend's user. When you are done:

```sh
kubectl -n capm delete pod capm-maint
kubectl -n capm scale deploy/backend --replicas=1
kubectl -n capm rollout status deploy/backend
kubectl -n argocd patch application capm --type merge \
  -p '{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true,"allowEmpty":false}}}}'
```

## Restore

Use this after losing the volume or the node, or to roll the registry back to a
snapshot. A snapshot holds two paths, recorded as the backup job saw them:
`/scratch/capm.db` (a consistent copy of the database) and `/data/blobs`.

Before starting (if the registry is still up), record a known bundle's digest
to compare afterwards:

```sh
curl -s https://capm.masondrake.dev/v1/bundles/<owner>/<name>/<version>   # note "digest"
```

1. Follow [Maintenance pod](#maintenance-pod) up to the `kubectl exec` shell.
   On a fresh PVC after a node loss, let ArgoCD create it first (sync, then
   scale the backend to 0 before the pod starts).
2. In the pod, fetch the snapshot:

   ```sh
   restic snapshots
   restic restore latest --target /restore
   ls -l /restore/scratch /restore/data   # expect capm.db and blobs
   ```

   To use an older snapshot, give its ID instead of `latest`.
3. Replace the live data. The stale `-wal` and `-shm` files must go: the
   database is in WAL mode, and an old WAL next to a restored `capm.db` would
   be replayed against the wrong file.

   ```sh
   rm -f /data/capm.db /data/capm.db-wal /data/capm.db-shm
   rm -rf /data/blobs
   cp -a /restore/scratch/capm.db /data/capm.db
   cp -a /restore/data/blobs /data/blobs
   ls -ln /data              # owner and group should be 65532 65532
   ```
4. Check the result before starting the backend:

   ```sh
   sqlite3 /data/capm.db 'PRAGMA integrity_check;'      # expect: ok
   sqlite3 /data/capm.db 'SELECT digest FROM versions;' | sed 's/^sha256://' |
     while read -r d; do [ -f "/data/blobs/$d" ] || echo "missing blob $d"; done
   ```

   Opening the database creates fresh `capm.db-wal` and `capm.db-shm` owned by
   65532; that is fine. A blob missing from the snapshot means the bundle was
   published after it was taken.
5. Leave the pod and scale up as described at the end of
   [Maintenance pod](#maintenance-pod).
6. Verify from your own machine. Pull the bundle and compare digests; the
   registry reports the expected digest and the download should hash to it:

   ```sh
   capm pull <owner>/<name>@<version>
   curl -s https://capm.masondrake.dev/v1/bundles/<owner>/<name>/<version>   # "digest"
   curl -s https://capm.masondrake.dev/v1/bundles/<owner>/<name>/<version>/download | sha256sum
   ```

   The `sha256sum` output must equal the part of `digest` after `sha256:`, and
   match the value you recorded before the restore.

Anyone who logged in after the snapshot has a token that no longer exists and
must run `capm login` again.

## Takedown runbook

capm v1 has no admin endpoints. The owner can yank a version, but nobody else
can, and tokens cannot be revoked (see
[security-notes.md](security-notes.md)). This runbook is a stand-in: you edit
the SQLite database directly with the backend stopped. It is for malware,
illegal content and compromised accounts, not routine use.

Follow [Maintenance pod](#maintenance-pod) up to the `kubectl exec` shell, then
open the database:

```sh
sqlite3 /data/capm.db
```

The relevant schema, from `backend/internal/store/store.go`:

| Table | Columns |
|---|---|
| `users` | `id` (GitHub numeric id), `login` (unique, case-insensitive) |
| `bundles` | `owner_id`, `name`; primary key `(owner_id, name)` |
| `versions` | `owner_id`, `name`, `version`, `digest` (`sha256:<hex>`), `yanked` (0 or 1), `manifest` (JSON), `created_at` (unix seconds); unique `(owner_id, name, version)` |
| `tokens` | `hash` (sha256 of the token, BLOB, primary key), `user_id`, `created_at` |

Logins of renamed accounts are tombstoned as `~<id>`; look up by `id` if the
login does not match.

Find what you are acting on:

```sql
SELECT u.id, u.login, v.name, v.version, v.digest, v.yanked
FROM versions v JOIN users u ON u.id = v.owner_id
WHERE u.login = 'alice';
```

### Yank a version

```sql
UPDATE versions SET yanked = 1
WHERE owner_id = (SELECT id FROM users WHERE login = 'alice')
  AND name = 'my-bundle' AND version = '1.0.0';
SELECT changes();   -- expect 1
```

This is the same flag the owner's `POST .../yank` sets. Yanking only hides the
version from `latest` resolution and adds a warning. **A yanked version can
still be pulled by anyone who asks for the exact version**, so yank is not a
takedown of malicious content. For that, remove it as below.

### Remove a version completely

```sql
-- Check whether another version has the same tarball (same digest).
SELECT owner_id, name, version FROM versions
WHERE digest = (SELECT digest FROM versions
                WHERE owner_id = (SELECT id FROM users WHERE login = 'alice')
                  AND name = 'my-bundle' AND version = '1.0.0');

DELETE FROM versions
WHERE owner_id = (SELECT id FROM users WHERE login = 'alice')
  AND name = 'my-bundle' AND version = '1.0.0';
SELECT changes();   -- expect 1

-- Only if no versions of the bundle remain; otherwise it lists as an empty bundle.
DELETE FROM bundles
WHERE owner_id = (SELECT id FROM users WHERE login = 'alice') AND name = 'my-bundle';
```

Then delete the blob, using the hex from the `digest` column without the
`sha256:` prefix:

```sh
rm /data/blobs/<hex>
```

Consequences, from the code:

- Blobs are content-addressed and shared. Publishing the same tarball under two
  versions or two bundles writes one file. Delete the blob only if the first
  query above shows no other row with that digest; otherwise those versions
  would still have a row but no file, and downloading them would fail.
- Delete the row before, or together with, the file. A `versions` row with no
  blob makes `download` return a 500 (`store.Blob` reads the file after
  finding the row).
- Version immutability is enforced by the `UNIQUE(owner_id, name, version)`
  row. Once the row is gone, the owner can publish that version number again
  with different content. Clients that saw the old digest will see a different
  one.
- Existing restic snapshots still contain the blob and the old database. To
  purge it from R2 as well, find the snapshots (`restic snapshots`) and run
  `restic forget --prune <snapshot-id>` for each that holds it, or wait for the
  retention window (7 daily, 4 weekly) to expire them. Restoring an old
  snapshot brings the content back.

### Invalidate a user's tokens

Tokens are stored only as hashes, so you cannot pick out one token from the
database; delete all of the user's tokens:

```sql
DELETE FROM tokens
WHERE user_id = (SELECT id FROM users WHERE login = 'alice');
SELECT changes();   -- number of tokens removed
```

The holder gets `401` on their next request. This does **not** stop them: any
GitHub account can run `capm login` and receive a new token. Pair it with
removing what they published, and for sustained abuse block them at
Cloudflare. Do not delete the `users` row: `bundles` and `tokens` reference it
(the backend opens the database with foreign keys on, but the `sqlite3` shell
does not, so it would let you leave orphaned rows).

Leave `sqlite3` with `.quit`, then scale back up as described at the end of
[Maintenance pod](#maintenance-pod).

## Rollback

Rollouts are commits, so a rollback is a revert. Find the deploy commit and
revert it on `main`:

```sh
git log --oneline --grep='^chore: deploy' -5
git revert <deploy-commit-sha>
git push origin main
```

The revert restores the previous image tags in `k3s/apps/`, touches only
`k3s/**`, so it does not retrigger CI, and ArgoCD syncs it. Because the
backend uses `Recreate`, the old pod stops before the previous version starts.
A rollback does not undo data changes: if a new version migrated the database,
restore from a snapshot (above) as well.
