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
capm push ./my-bundle              # publishes <your-login>/<metadata.name>@<metadata.version>
capm search reviewer               # bundles whose owner, name or description contains "reviewer"
capm list alice                    # alice's bundles; without an owner, every bundle
capm inspect alice/pr-reviewer@0.1.0   # declared permissions, without installing
capm pull alice/pr-reviewer@0.1.0  # unpacks into ./pr-reviewer after checking the sha256 digest
capm run alice/pr-reviewer@0.1.0 --model-url https://models.example.com --allow-unenforced-egress
capm inspect alice/pr-reviewer@0.2.0 --diff   # what changed since the version you last ran
capm known                         # bundles capm remembers (pinned owners, last run)
capm known forget alice/pr-reviewer
capm version                       # which build you are running
```

`search` and `list` need no login. They print one bundle per line (name, latest
installable version, first line of its description) and show `-` as the
version when every version is yanked. Descriptions are written by the
bundle's author and unverified. Output stops at 2000 bundles; narrow it with
`search`.

`inspect` and `run` also take a local bundle directory. Omitting `@version`
means the latest non-yanked version. Always pin the version you inspected:
the latest version can change between `inspect` and `run`.

`capm run` shows the declared permissions and its run plan, asks you to
confirm (`--yes` skips the question), then drives sbx. Today it always needs
`--allow-unenforced-egress`, because capm cannot restrict the sandbox to the
listed hosts (see the security notes). It also refuses while a global sbx
`anthropic` secret is stored, unless you pass `--allow-global-anthropic-secret`.
Mount paths in the manifest are resolved under `--workdir` (default: the
current directory).

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
- `capm known forget owner/name` deletes a record; deleting the file forgets
  everything. A corrupt file is ignored with a warning and replaced on the next
  recorded run.

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
