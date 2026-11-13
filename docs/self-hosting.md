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

The restore procedure (and the SQL fallback of the takedown runbook) needs the backend scaled to 0. The
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

Restore and the takedown runbook's SQL fallback use a one-off pod built from the backup image (it has
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

Use the registry's admin API through `capm admin`. It is for malware, illegal
content and abusive accounts, not routine use. An owner can only yank their own
versions, and a yank is advisory (see below); removal and bans are admin-only.

### Prerequisites

- Your GitHub numeric id is in `ADMIN_GITHUB_IDS` (comma-separated ids, never
  logins) in `k3s/apps/backend/configmap.yaml`. Changing it needs a backend
  restart (`kubectl -n capm rollout restart deploy/backend`), since a ConfigMap
  change alone does not restart pods. A malformed value stops the server from
  starting, with the offending entry in the log.
- You are logged in as that account (`capm login`). Anyone else gets
  `not found (are you an admin on this registry?)`: `/v1/admin/*` answers 404
  to everyone who is not an admin, so it is not advertised.

### Commands

```sh
capm admin remove  alice/my-bundle@1.0.0 --reason "contains credential stealer"
capm admin remove  alice/my-bundle       --reason "malware"       # every version
capm admin restore alice/my-bundle@1.0.0                          # undo a removal
capm admin ban     alice  --reason "publishing malware"           # login or numeric id
capm admin unban   alice
capm admin log                                                    # audit trail, newest first
```

`--reason` is required for `remove` and `ban` (at most 500 characters). It is
shown to users, so write it for them.

### What each action does

- **Yank** (owner's `capm`/API call, not an admin action) only hides a version
  from `latest` and adds a warning. Anyone can still pull the exact version.
  Yank is not a takedown.
- **Remove** marks the version removed with your reason. `download`, `metadata`
  and `resolve` then return `410 Gone` with the reason, and `capm pull`, `run`
  and `inspect` print `removed by the registry: <reason>` and exit 1. Removed
  versions are skipped when computing `latest`, stay in the versions list
  flagged removed (the website shows the reason and offers no install commands),
  and their manifest is no longer served. The version row stays, so the number
  can never be published again. The blob file is deleted unless another live
  version, of any owner, has the same digest (blobs are content-addressed and
  shared); the response says how many blobs were deleted.
- **Restore** brings a removed version back only if its blob still exists. If
  the blob was deleted you get `409`; put the file back at
  `/data/blobs/<hex>` (for example from a restic snapshot, see
  [Restore](#restore)) and retry. For a whole bundle, versions without a blob
  are skipped and reported.
- **Ban** stops the user's tokens working (`401`), refuses to issue them a new
  token at login (`403`), and hides their bundles: they vanish from `list` and
  `search`, and every direct bundle route answers `404` as if the bundle did not
  exist. Nothing is deleted; remove their versions separately if needed. Admins
  cannot be banned. `unban` always works and restores visibility. A ban does not
  stop someone making a new GitHub account.
- Every admin action writes a row to `admin_actions` in the same transaction as
  the change. `capm admin log` shows them.

### Backups

A removed blob is deleted from the volume but stays in restic snapshots until
they age out (retention: 7 daily, 4 weekly), and so does the old database. In
urgent cases purge it from R2 as well: find the snapshots with
`restic snapshots` and run `restic forget --prune <snapshot-id>` for each that
holds the content. Restoring an old snapshot brings the content back.

### If the API is unusable

If the backend is down or admin login is impossible, edit the database
directly. Follow [Maintenance pod](#maintenance-pod) (backend at 0 replicas,
ArgoCD paused) up to the `kubectl exec` shell, then `sqlite3 /data/capm.db`.
The `sqlite3` shell runs with foreign keys off, so do not delete `users` rows.

Schema (schema version 6, which also has a `downloads` table of per-day request counts; see `backend/internal/store/migrate.go`):

| Table | Columns |
|---|---|
| `users` | `id` (GitHub numeric id), `login` (unique, case-insensitive; renamed accounts are tombstoned as `~<id>`) |
| `bundles` | `owner_id`, `name` |
| `versions` | `owner_id`, `name`, `version`, `digest` (`sha256:<hex>`), `yanked`, `manifest` (JSON), `created_at`, `removed` (0 or 1), `removed_reason`, `size` (blob bytes), `readme` (author text, may be empty) |
| `tokens` | `hash` (sha256 of the token, primary key), `user_id`, `created_at`, `id` (public handle, unique), `name`, `expires_at` (unix seconds, NULL = never), `last_used_at`, `revoked_at` (NULL = live) |
| `banned_users` | `user_id` (primary key), `reason`, `created_at` |
| `admin_actions` | `id`, `admin_id`, `action`, `target`, `reason`, `created_at` |
| `schema_version` | `version` (one row) |

Remove a version, with its audit row (the id is the admin's GitHub id):

```sql
BEGIN;
UPDATE versions SET removed = 1, removed_reason = 'contains malware'
WHERE owner_id = (SELECT id FROM users WHERE login = 'alice')
  AND name = 'my-bundle' AND version = '1.0.0';
SELECT changes();   -- expect 1
INSERT INTO admin_actions(admin_id, action, target, reason, created_at)
VALUES (139420415, 'remove_version', 'alice/my-bundle@1.0.0', 'contains malware', strftime('%s','now'));
COMMIT;

-- Delete the blob only if this returns 0 (no live version shares the digest):
SELECT count(*) FROM versions
WHERE removed = 0 AND digest = (SELECT digest FROM versions
  WHERE owner_id = (SELECT id FROM users WHERE login = 'alice')
    AND name = 'my-bundle' AND version = '1.0.0');
```

```sh
rm /data/blobs/<hex>      # the digest without the sha256: prefix
```

Never `DELETE` a `versions` row: the row is what stops the number being
published again with different content.

Ban a user:

```sql
BEGIN;
INSERT INTO banned_users(user_id, reason, created_at)
VALUES ((SELECT id FROM users WHERE login = 'alice'), 'publishing malware', strftime('%s','now'));
INSERT INTO admin_actions(admin_id, action, target, reason, created_at)
VALUES (139420415, 'ban_user', 'user:' || (SELECT id FROM users WHERE login = 'alice'), 'publishing malware', strftime('%s','now'));
COMMIT;
```

Invalidate a user's tokens. Normally use `capm admin revoke-tokens <login|id>`,
which does this and writes the audit row. It stops existing tokens only; a
banned user is refused new ones, an unbanned user can log in again. The SQL
fallback revokes rather than deletes, so token ids are never reused (the id is
the admin's GitHub id, as above):

```sql
BEGIN;
UPDATE tokens SET revoked_at = strftime('%s','now')
WHERE user_id = (SELECT id FROM users WHERE login = 'alice') AND revoked_at IS NULL;
SELECT changes();   -- number of tokens revoked
INSERT INTO admin_actions(admin_id, action, target, reason, created_at)
VALUES (139420415, 'revoke_tokens', 'user:' || (SELECT id FROM users WHERE login = 'alice'), '', strftime('%s','now'));
COMMIT;
```

Do not `DELETE` token rows by hand: the server picks new token ids as the
highest existing id plus one, so deleting the newest rows lets an id be handed
out twice.

Leave `sqlite3` with `.quit`, then scale back up as described at the end of
[Maintenance pod](#maintenance-pod).

## Quotas

Because `local-path` does not enforce the volume size, the backend limits what
can be stored. All four limits are environment variables with defaults, so the
ConfigMap does not set them; `0` disables a limit, and a negative or
non-numeric value stops the backend from starting (the offending variable is in
the log).

| Variable | Default | Limits |
| --- | --- | --- |
| `MAX_USER_BYTES` | 100 MiB | stored tarballs per owner (a digest shared by several of an owner's versions counts once; yanked versions count; removed versions do not) |
| `MAX_USER_BUNDLES` | 50 | bundle names per owner (a name with only removed versions still counts) |
| `MAX_BUNDLE_VERSIONS` | 200 | versions per bundle, yanked and removed included |
| `MAX_TOTAL_BYTES` | 3 GiB | stored bytes across the whole registry; keep it under the volume size and the 4Gi `CapmDataVolumeFilling` alert |

Admins are subject to the same limits. To give one user different limits (an
override replaces the default for that user; it does not stack):

```sh
capm admin quota alice                          # usage, limits, and whether each is an override
capm admin quota alice --bytes 500MiB --bundles 100
capm admin quota alice --bytes 2GiB             # changes bytes only; keeps a bundles override
capm admin quota alice --bytes 0                # unlimited bytes for this user
capm admin quota alice --reset                  # back to the defaults
```

Sizes accept plain bytes or `KiB`/`MiB`/`GiB`/`TiB` (and `KB`/`MB`/`GB`/`TB`
for powers of 1000). Overrides are audited (`capm admin log`). Changing a
default means editing the variable (add it to the backend ConfigMap, then
`kubectl -n capm rollout restart deploy/backend`); an override takes effect at
once.

What users see: `capm usage` prints their storage, bundle count and the
per-bundle version limit. A `capm push` over a per-user or per-bundle limit
exits 1 with the server's sentence, for example `storage limit reached: you
store 99.0 MiB of your 100.0 MiB limit and this bundle would exceed it...`
(HTTP 413, body `{"error": ..., "limit": "user_bytes", "used": N, "max": N}`;
`limit` is one of `user_bytes`, `user_bundles`, `bundle_versions`). Over
`MAX_TOTAL_BYTES` the answer is HTTP 507 `{"error": "the registry is full ...",
"limit": "total_bytes"}` with no registry-wide numbers, and the backend logs a
line starting `WARN: quota: registry storage limit total_bytes reached` each
time. There is no metrics alert for it yet (that arrives with the metrics
endpoint); until then watch the logs and the volume alert. A rejected publish
still counts against the user's hourly publish allowance, and leaves nothing on
disk. A limit never affects downloads: users already over a limit can still
pull, and are only blocked from publishing more bytes. Re-publishing bytes the
user already stores adds nothing. A restore of a removed version is not
quota-checked.

## Reports

Anyone can report a bundle, from the bundle page ("Report this bundle"), with
`capm report <owner/name[@version]> --reason malware|secrets-exposed|impersonation|other
[--details TEXT]`, or `POST /v1/bundles/{owner}/{name}/report`. No account is
needed. A report removes nothing by itself.

**Where reports go.** They are stored in the `reports` table (migration 7). With
`REPORT_WEBHOOK_URL` unset, which is how this is deployed, nothing notifies
you: look yourself.

```sh
capm admin reports              # open reports, newest first
capm admin reports --all        # or --resolved
capm admin report 12            # one report in full
capm admin resolve 12 --note "removed alice/x@1.0.0"
```

Each row shows the bundle's current state next to the report (`live`,
`removed`, `owner-banned`), so you can see what is already handled. Taking a
bundle down (`capm admin remove`, `ban`) does not resolve its reports; resolve
them yourself, which is audited (`capm admin log`). The text of a report is
written by a stranger: the CLI strips control and bidi characters, but treat it
as untrusted input.

**Limits.** 5 reports per client IP per hour (`REPORT_RATE_PER_HOUR`; `0`
switches reporting off, and the route answers 404). The client IP uses the same
`TRUSTED_PROXY` / `CLIENT_IP_HEADER` logic as the login limiter, so read
[Client IP header](#client-ip-header). At most 200 open reports per bundle and
5000 in all; beyond that new reports are accepted and dropped (the reporter
sees the usual success) and the backend logs `WARN: reports: open-report cap
reached`. Resolving reports frees room. An identical open report (same bundle,
version, reason and reporter) within 24 hours is not stored again.

**The website form and the visitor IP.** The form calls the registry from the
frontend server, so the backend would see the frontend pod. The frontend
forwards the visitor's address taken from `CF-Connecting-IP` (set by Cloudflare;
override the name with `CLIENT_IP_HEADER` on the frontend) as the only
`X-Forwarded-For` entry. That only works if Cloudflare's header reaches the
frontend pod through the tunnel and Traefik, and if the backend has
`TRUSTED_PROXY=true` (it does). Verify with the same throwaway `whoami` check as
in [Client IP header](#client-ip-header), on the frontend path. If the header
is absent, the form falls back to sending nothing, and every website report
shares one bucket (5 an hour for the whole site; CLI and API callers are
limited separately per address).

**Turning the webhook on later (not applied; nothing here exists in the
cluster).** The URL is a credential, so keep it in a SealedSecret, the same way
as the backup secret above:

```sh
kubectl create secret generic report-webhook -n capm --dry-run=client -o yaml \
  --from-literal=REPORT_WEBHOOK_URL='https://hooks.example.com/<secret path>' \
| kubeseal --controller-namespace kube-system \
    --controller-name sealed-secrets-controller -o yaml > k3s/apps/backend/report-webhook-sealed-secret.yaml
```

Commit the sealed file, then reference it from the backend Deployment
(`k3s/apps/backend/deployment.yaml`) next to the existing `envFrom`:

```yaml
          envFrom:
            - configMapRef:
                name: backend-config
            - secretRef:           # NOT APPLIED: add only when enabling the webhook
                name: report-webhook
```

Optionally add `PUBLIC_URL: "https://capm.masondrake.dev"` to the backend
ConfigMap so messages link to the bundle page. The backend POSTs JSON
`{"text", "bundle", "version", "reason", "reportId", "details", "url"}` for each
newly stored report (never for a duplicate or a dropped one): asynchronous, 5
second timeout, no retries, a full queue (32) drops with a WARN, and a failing
receiver never affects the reporter. `text` is one line built from the reason
and bundle only; the reporter's free text is only in `details`, truncated to 200
characters, so a chat relay that interprets `text` cannot be injected through
it. The URL is never logged, only its host. An `http://` or `https://` value is
required or the backend refuses to start. After changing it, restart the
backend.

## Before deploying a release that migrates the database

The backend applies schema migrations when it starts, so a merge to `main` that
adds one migrates the live database during the deploy. Migrations are
additive and each runs in a transaction, but take a manual backup first so
there is a snapshot from just before:

```sh
kubectl -n capm create job --from=cronjob/capm-backup backup-pre-migrate
kubectl -n capm logs -f job/backup-pre-migrate     # wait for it to finish
kubectl -n capm delete job backup-pre-migrate      # afterwards
```

**This release (schema version 7) migrates again, for abuse reports (step
7).** It adds one table, `reports`, and two indexes on it (`reports_open`, a
partial index over unresolved reports, newest first; `reports_dedup` over
owner, name, reporter key and time). No existing table changes, so the step is
quick and cannot alter data. **Take the backup above first.** A release older
than 7 refuses to start on a version-7 database ("newer than this server
supports"), so a rollback needs the pre-migration snapshot; reports filed since
the deploy are lost with it. See [Reports](#reports).

**Schema version 6 migrated for download counts (step 6).** It adds one table, `downloads(owner_id, name, version, day, count)`
(`day` is days since the Unix epoch, UTC) and an index on `day`; no existing
table changes. Counts start at zero. At every start the backend also rolls
daily rows older than 400 days into one row per version with `day = 0`, so
all-time totals stay correct (idempotent, one transaction). Take the backup
above first. A release older than 6 refuses to start on a version-6 database,
so a rollback needs the pre-migration snapshot or a roll-forward fix; a
rolled-back-and-forward registry keeps its counts, it just does not count
while the old release runs.

**Schema version 5 migrated for README support (step 5).** It adds one column, `versions.readme TEXT NOT NULL DEFAULT ''`; existing
versions keep an empty README (no backfill from blobs). Take the backup above
first. A release older than 5 refuses to start on a version-5 database ("newer
than this server supports"), so a rollback needs the pre-migration snapshot or
a roll-forward fix.

**Schema version 4 migrated for [quotas](#quotas).** It
adds `versions.size` and a `quota_overrides` table. Every start then fills in
any missing `size` by statting the blob files (idempotent; a missing blob counts
as 0 bytes and is logged once), so it also repairs rows a rolled-back release
inserted. The default limits start enforcing on the first publish after the
deploy, so check beforehand that nobody is already over them. Stop the backend
and open the [maintenance pod](#maintenance-pod), then run this read-only query
(it only uses columns that exist before migration 4):

```sh
sqlite3 -readonly -header -column /data/capm.db "SELECT u.login, count(DISTINCT v.name) AS bundles, count(*) AS versions, (SELECT max(c) FROM (SELECT count(*) AS c FROM versions WHERE owner_id = u.id GROUP BY name)) AS most_versions_in_one_bundle FROM users u JOIN versions v ON v.owner_id = u.id GROUP BY u.id ORDER BY bundles DESC;"
```

Compare `bundles` with 50 (`MAX_USER_BUNDLES`) and `most_versions_in_one_bundle`
with 200 (`MAX_BUNDLE_VERSIONS`). Bytes cannot be computed from SQL before the
migration (there is no `size` column yet); the whole-registry figure is
`du -sh /data/blobs` against the 3 GiB `MAX_TOTAL_BYTES`. Per-owner bytes are
available after the deploy with `capm admin quota <login>`. Anyone found over a
limit is not locked out of anything: they can still pull, and only publishing
more is refused until you raise their limit with `capm admin quota <login>
--bytes ... --bundles ...` or they remove versions. If the query shows someone
over a count limit, raise the default in the ConfigMap or give them an override
right after the deploy.

**Schema version 3 migrated the token table.** Every token
issued before the deploy gets an expiry of 90 days after the deploy, so users
who never log in again will be logged out then (`capm login` fixes it, and
capm warns during the last 7 days). Announce it in the release notes. New
tokens expire after `TOKEN_TTL_DAYS` (default 90; the ConfigMap does not set it).

Rolling back the image does not undo a migration. The previous release ignores
the extra columns and tables and keeps working, but removed versions would
appear live again to it, and so would revoked and expired tokens (the old
release ignores `revoked_at` and `expires_at`, and tokens it issues never
expire); restore from the snapshot (above) if you need the old
state exactly. A server refuses to start on a database whose
`schema_version` is newer than it knows.

Expired and revoked token rows older than 30 days are deleted at every startup.

Removed blobs remain in restic snapshots (including this one) until they age out.

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
