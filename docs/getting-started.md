# Getting started with capm v1

capm is a registry for agent bundles: a `capm.yaml` manifest plus optional
context files, run on a base agent (Claude Code or OpenCode) inside a Docker
Sandbox (`sbx`). This page covers running the registry locally and using the
CLI. Read [security-notes.md](security-notes.md) before running anyone
else's bundle.

## Install

```sh
curl -fsSL https://capm.masondrake.dev/install.sh | sh
```

This downloads the latest `capm` release binary for your OS and CPU (macOS or
Linux, amd64 or arm64) from GitHub Releases, verifies its SHA-256 against the
release's `checksums.txt`, and installs it to `~/.local/bin/capm`. It never
uses sudo. Set `CAPM_INSTALL_DIR` to install somewhere else:

```sh
curl -fsSL https://capm.masondrake.dev/install.sh | CAPM_INSTALL_DIR=/usr/local/bin sh
```

If the install directory is not on your `PATH`, the script prints the
`export PATH=...` line to add. Building from source still works; see
[Build](#build).

### Updating

```sh
capm self-update --check   # prints "current <v> latest <v>"; changes nothing
capm self-update           # download, verify, replace this binary
```

`self-update` downloads the latest release for your OS and CPU, checks its
SHA-256 against the release's `checksums.txt` (a mismatch changes nothing and
exits 1), and swaps the binary in place atomically. It refuses when the
directory is not writable, or when capm was installed by Homebrew or Nix (use
that package manager). A build that is not a released version (`dev` or a
commit hash) counts as out of date and is updated. Re-running the installer
above does the same job. Release builds are tagged `vX.Y.Z`; per-commit builds
are prereleases the installer never picks.

capm also checks for a newer release at most once every 24 hours, after a
command finishes successfully, and prints one line on stderr:
`a newer capm is available (0.2.0); run capm self-update`. The check is a plain
GET of the GitHub releases page (user agent `capm/<version>`, nothing else sent),
gives up after 1.5 seconds and never fails a command. It stays silent when
stderr is not a terminal, when `CI` is set, for non-release builds, and when
you set `CAPM_NO_UPDATE_CHECK=1` (any non-empty value). `CAPM_DOWNLOAD_BASE`
overrides the download URL, as for the installer, and `CAPM_LATEST_URL` the page
that names the latest tag.

## Prerequisites

- Go 1.27.3 or newer (the version in `go.work` and each `go.mod`)
- Node.js 22 and npm (frontend)
- Docker with Compose v2.24 or newer, only for `make up`
- `sbx` (Docker Sandboxes) v0.48 or newer, signed in with `sbx login`, only
  for `capm run`. capm's sbx integration has not been run against a real
  sandbox yet; see [sbx-findings.md](sbx-findings.md).
- A GitHub account, to publish

## Build

```sh
make build        # bin/capm-backend, bin/capm, and a production frontend build
```

The three Go modules (`manifest`, `backend`, `cli`) are tied together by
`go.work` and `replace ../manifest` directives, so `go install
github.com/MasonD-007/capm/cli@latest` does **not** work. Build from a clone
and put `bin/capm` on your `PATH`.

## Create a GitHub OAuth app (for logins)

The registry signs publishers in with GitHub's device flow. Pulling needs no
account.

1. GitHub, Settings, Developer settings, OAuth Apps, New OAuth App. Any
   homepage and callback URL will do (for example `http://localhost:3000`);
   the device flow does not use the callback.
2. Tick **Enable Device Flow** and save.
3. Copy the **Client ID**. No client secret is needed.

## Run the registry

Copy `backend/.env.example` to `backend/.env` and set at least
`GITHUB_CLIENT_ID`. Without it, `/v1/auth/*` returns 503 and nobody can log in.

| Variable | Default | Meaning |
|---|---|---|
| `GITHUB_CLIENT_ID` | (none) | OAuth app client ID, Device Flow enabled |
| `GITHUB_API_URL` | `https://api.github.com` | GitHub REST base (tests, Enterprise) |
| `GITHUB_OAUTH_URL` | `https://github.com` | GitHub OAuth base (tests, Enterprise) |
| `PORT` | `8080` | listen port (compose fixes it to 8080) |
| `DATA_DIR` | `./data` | database and bundle storage (compose fixes it to `/data`) |
| `MAX_BUNDLE_BYTES` | `5242880` | largest accepted upload |
| `PUBLISH_RATE_PER_HOUR` | `30` | publishes per user per hour |
| `AUTH_RATE_PER_MINUTE` | `30` | auth requests per client IP per minute |
| `TRUSTED_PROXY` | `false` | trust `X-Forwarded-For`; only behind a proxy that sets it |

Then either:

```sh
make up           # docker compose: backend on :8080, website on :3000
```

Compose reads `backend/.env` at run time (it is never copied into the image).
Variables exported in your shell are not forwarded; put them in the file.

or, without Docker:

```sh
make backend      # builds and runs bin/capm-backend from backend/ (reads backend/.env, data in backend/data)
make install && make frontend   # Next.js dev server on :3000, reading API_URL (default http://localhost:8080)
```

## Use the CLI

```sh
export CAPM_REGISTRY=http://localhost:8080   # needed for local development; the default is https://capm.masondrake.dev

capm login                         # GitHub device flow; prints a URL and a code
capm whoami                        # your login on stdout; asks the registry whether the stored token still works
capm init ./my-bundle              # writes a commented capm.yaml (asks questions on a terminal)
capm lint ./my-bundle              # checks the bundle before you publish it
capm push ./my-bundle              # publishes <your-login>/<metadata.name>@<metadata.version>
capm tokens                        # your login tokens (id, name, last used, expiry); * marks this machine
capm tokens revoke 7               # revoke one, e.g. a lost laptop
capm logout                        # revoke this machine's token and delete the stored credentials
capm search reviewer               # bundles whose owner, name or description contains "reviewer"
capm list alice                    # alice's bundles; without an owner, every bundle
capm list --sort downloads         # most downloaded in the last 30 days first (also: recent, name; works on search too)
capm inspect alice/pr-reviewer@0.1.0   # declared permissions, without installing
capm pull alice/pr-reviewer@0.1.0  # unpacks into ./pr-reviewer after checking the sha256 digest
capm run alice/pr-reviewer@0.1.0 --model-url https://models.example.com --allow-unenforced-egress
capm inspect alice/pr-reviewer@0.2.0 --diff   # what changed since the version you last ran
capm outdated                      # bundles you have run that have a newer version, and what it changes
capm known                         # bundles capm remembers (pinned owners, last run)
capm known forget alice/pr-reviewer
capm version                       # which build you are running
```

`search` and `list` need no login. They print one bundle per line (name, latest
installable version, first line of its description) and show `-` as the
version when every version is yanked. When the registry flags any bundle, a
marker column appears before the description: `!!` means a high risk label and
`!` a caution one. That marker is the registry's claim, and a blank is not an
endorsement (it also appears for info-only bundles and registries that do not
report risk); `capm inspect` shows the labels computed locally. Descriptions
are written by the bundle's author and unverified. `--sort recent` orders by
the newest version's date and `--sort downloads` by download requests over the
last 30 days; each adds a column (`YYYY-MM-DD`, or the count) before the
description, and the flag may come before or after the owner or search text.
Download counts are raw request counts that anyone can inflate, not a trust
signal. A registry that predates sorting is noted once on stderr and shown in
its default order. Output stops at 2000 bundles; narrow it with
`search`.

`inspect` and `run` also take a local bundle directory. Omitting `@version`
means the latest non-yanked version. Always pin the version you inspected:
the latest version can change between `inspect` and `run`.

`inspect` ends with a "Risk labels" section, and `run` prints the same section
before it asks you to confirm. The labels are computed locally from the
manifest and describe what the bundle declares it can reach (read-write
mounts, many egress hosts, secrets, MCP servers, context files); they are not
a review, and no labels is not an endorsement. See "What the risk labels mean"
in the security notes for every rule.

`capm run` shows the declared permissions and its run plan, asks you to
confirm (`--yes` skips the question), then drives sbx. Today it always needs
`--allow-unenforced-egress`, because capm cannot restrict the sandbox to the
listed hosts (see the security notes). It also refuses while a global sbx
`anthropic` secret is stored, unless you pass `--allow-global-anthropic-secret`.
Mount paths in the manifest are resolved under `--workdir` (default: the
current directory).

### Write your first bundle

```sh
capm init my-agent         # questions on a terminal; or: capm init my-agent --yes --name my-agent
cd my-agent
$EDITOR capm.yaml prompts/system.md    # describe it, write the prompt
capm lint                  # problems, warnings, then the risk labels
capm inspect .             # the permissions you are declaring
capm login                 # once
capm push .                # publishes <your-login>/my-agent@0.1.0
```

`init` writes a commented `capm.yaml` and, if you want, a placeholder
`prompts/system.md`. The defaults are the most restrictive: version `0.1.0`, no
egress hosts, no mounts, no secrets, no MCP servers. Answer the questions (or
pass `--egress`, `--mount path:mode`, `--secret NAME`, `--base`, ... with
`--yes`) to widen them. `init` refuses to run where a `capm.yaml` exists and never
overwrites a file.

Only `capm.yaml`, the files listed under `context` and a root `README.md` are
published. `capm lint` reports (`error[id]` / `warning[id]` on stderr, risk
labels on stdout; exit 0 with no errors, 1 with errors or, with `--strict`, any
warning, 2 for usage mistakes):

| Rule | Severity | Meaning |
|---|---|---|
| `context_missing` | error | a listed context file does not exist or is not a plain file, so push would fail |
| `secret_file` | error | a file that would be published looks like a credential |
| `secret_file_nearby` | warning | a credential-looking file sits in the directory but is not published |
| `context_unlisted` | warning | a file in the directory is not listed in `context`, so it is NOT published |
| `no_description`, `no_authors` | warning | the manifest has no description or authors |
| `size_near_limit` | warning | the packed bundle is over 80% of the 5 MiB publish limit |
| `version_not_bumped` | warning | the version already exists on the registry or is lower than the latest (needs `capm login`; skipped with `--offline`; a network failure skips it with a note) |

The secret check looks at what would be published, by file name (`.env`,
`.env.*` except `.env.example`/`.sample`/`.template`, `*.pem`, `*.key`,
`id_rsa`, `id_ed25519`, `credentials.json`, `.npmrc`, `.netrc`) and by content
(private-key headers and GitHub, AWS, Slack and Anthropic token shapes). It
prints the file, line and pattern name, never the matched text. It is a
safety net for common mistakes, not a guarantee. `capm push` runs the two
error-level checks before it sends anything and refuses if either fires; if a
flagged file really is meant to be public, `capm push --allow-secret-files`
turns the `secret_file` error into a warning. The other rules are not run by
`push`.

### What capm remembers

For every registry bundle you pull or run, capm keeps a record in
`known.json` in the capm config directory (next to `credentials.json`; for
example `~/.config/capm/known.json` on Linux and
`~/Library/Application Support/capm/known.json` on macOS; mode 0600). It holds
the bundle owner's GitHub account id, and for runs the version, digest and
manifest of the last run you confirmed. Nothing is written when you only
`inspect`, when you decline the confirmation, or for local directories.

- **Owner pinning.** If the registry later reports a different owner id for the
  same `owner/name`, `run` and `pull` refuse; `--accept-new-owner` proceeds and
  pins the new id. Registries that do not send an owner id get a warning, not a
  pin.
- **Permission diff.** Running a different version than last time first shows
  `Changes since the version you last ran (X -> Y)` with `+` added, `-` removed
  and `~` changed lines (egress, mounts, secrets, MCP servers, base agent,
  context files). If anything was added or widened, `--yes` does not skip the
  confirmation; use a terminal, or pass `--accept-permission-changes` to run
  non-interactively. If the same version is served with a different digest, the
  run is refused unless you pass `--accept-changed-digest`.
- **`capm outdated`.** Lists, from the same file, the bundles you have run on
  this registry whose latest installable version differs from the one you ran:
  `owner/name  ran  latest  changes`, where changes is e.g. `adds 2 egress
  hosts, 1 secret; widens 1 mount` or `no permission changes`. It only asks the
  registry (metadata, never the bundle), runs nothing and writes nothing.
  Bundles that were removed, are gone, changed owner or could not be reached get
  a row saying so. With nothing recorded it says so; when all are current it
  prints `all N bundles are up to date`.
- `capm known forget owner/name` deletes a record; deleting the file forgets
  everything. A corrupt file is ignored with a warning and replaced on the next
  recorded run.

### README on the website

A bundle may include a `README.md` at its root (a regular file; a symlink,
a directory or a README in a subfolder is ignored). `capm push` packs it
without it being listed in `context`, and the registry shows it on the bundle's
web page under "README: from the author, unverified". It is stored at publish
time, capped at 64 KiB (longer text is cut with a marker line; invalid UTF-8 is
replaced), and not checked by the registry. The website renders Markdown with
raw HTML off and does not load images. Versions published before this feature
have no README; publish a new version to add one. Note that clients older than
this release refuse to unpack a bundle that contains an undeclared `README.md`,
so update the CLI before relying on it.

### Environment variables the CLI reads

| Variable | Used by | Meaning |
|---|---|---|
| `CAPM_REGISTRY` | all | registry base URL (default `https://capm.masondrake.dev`; set `http://localhost:8080` for local development) |
| `CAPM_MODEL_URL` | run | your model endpoint, an https URL on port 443 (or `--model-url`) |
| `CAPM_MODEL_KEY` | run | key for that endpoint (or `--model-key`, which other processes can see) |
| `CAPM_MODEL` | run | model id; required for OpenCode (or `--model`) |
| `CAPM_SECRET_<NAME>` | run | value for the bundle's declared secret `NAME` |

Secret values come from `CAPM_SECRET_<NAME>` or, on a terminal, a hidden
prompt. capm does **not** read them from the sbx secret store. They are
written to a 0600 file in a capm temp directory for sbx to read and removed
when the run ends.

Credentials from `capm login` are stored in your user config directory
(`~/Library/Application Support/capm/credentials.json` on macOS,
`~/.config/capm/credentials.json` on Linux).

Login tokens expire after 90 days. capm prints `your capm token expires in N
days; run capm login` on stderr when a command that signs in finds fewer than
7 days left; run `capm login` again to get a new token. `capm logout` revokes
the token on the registry before deleting the credentials; if the registry is
unreachable it still deletes them locally and tells you the token may remain
valid until it expires. `capm tokens` and `capm logout` need a registry that
supports token management and say so when it does not.
