# capm v1 security notes

What capm v1 does and does not protect you from. Read this before running a
bundle you did not write. Setup is in [getting-started.md](getting-started.md).

## Declared is not enforced

`capm inspect` and the website show what a bundle **declares**: egress hosts,
mounts, secrets, MCP servers, context files, plus the base agent's own hosts.
That is a statement by the publisher, checked for form, not a sandbox
guarantee.

- **Egress is NOT enforced by `capm run` in v1.** sbx's default network
  policy is a broad allowlist, and the per-sandbox rules capm can add only
  widen it. Restricting a sandbox to exactly the listed hosts needs
  `sbx policy init deny-all`, which changes every sandbox on the machine;
  capm does not do that for you and cannot yet read back the effective
  policy. This is why `capm run` refuses to start without
  `--allow-unenforced-egress`, and why every inspect output carries the
  "Egress enforcement: NOT enforced yet" line.
- **The base agent has its own egress.** The Claude Code kit reaches the
  Anthropic hosts listed under "Base agent" whatever the bundle declares. The
  OpenCode kit allows a broad multi-provider list that capm does not
  enumerate; treat an OpenCode bundle's egress as effectively unrestricted.
  These host lists come from sbx documentation and are unverified.
- **Global sbx secrets can leak into a bundle sandbox.** sbx's proxy injects a
  globally stored service secret (for example `anthropic`) into requests to
  that service's hosts. A bundle on Claude Code can reach `api.anthropic.com`
  and so could spend your Anthropic credentials even if you gave it another
  model endpoint. `capm run` refuses while `sbx secret ls --global` shows an
  `anthropic` secret (or cannot be listed) unless you pass
  `--allow-global-anthropic-secret`, and warns about any other global secret.
- **Where secrets go.** A secret named by an MCP server travels only to that
  server, through the sbx MCP gateway on your machine. Any other declared
  secret is offered by the sbx proxy on requests to every host in the
  bundle's egress list. Your model key goes only to your model host. The run
  screen lists each secret's destinations.
- **Host skills.** `capm run` creates sandboxes with `--skills off`, so your
  own sbx skills store is not linked in.
- **MCP servers are remote only.** capm adds every MCP server with a header
  (sbx refuses headers on a URL that turns out to be a local, image-backed
  server) and then checks `sbx mcp inspect` for a remote endpoint at exactly
  the declared URL, aborting the run otherwise. Both behaviours come from sbx
  help text and are unverified. sbx rejects header-bearing MCP servers when
  your MCP gateway is the hosted one, so MCP bundles currently need a local
  gateway.

## Context files can carry prompt injection

Context files (prompts, instructions) are text the agent reads and obeys.
A bundle can use them to tell the agent to exfiltrate files from your mounts,
call its declared hosts with your data, or misuse an MCP server. `inspect`
lists the files but cannot tell whether their content is safe. Read them
(`capm pull`, then open them) before running a bundle with read-write mounts
or secrets.

## No signing; identity is a GitHub login

Bundles are not signed in v1. `capm pull` checks the download against the
sha256 digest the registry reports, which protects against corruption in
transit, not against a malicious or compromised registry. The only publisher
identity is the GitHub login in the bundle name (`login/name`).

## Login reassignment

The registry keys owners by GitHub numeric ID, but bundle names use the
login. If a GitHub user renames or deletes their account, someone else can
register that login on GitHub and then publish under the same `login/name`
(new versions; existing versions are immutable).

The CLI now pins owners. The registry reports the owner's numeric ID with
every resolve and metadata response. The first time you run or pull
`login/name` from a registry, capm records that ID in `known.json` (see
getting-started). On a later `run` or `pull`, a different ID makes capm refuse,
showing the pinned and the new ID and saying the name may have been taken over
by a different GitHub account. `--accept-new-owner` proceeds and re-pins.
`capm inspect` shows the pin status and never writes it.

Limits: pinning protects only a user who ran or pulled the bundle before, on
that machine; it does nothing on the first use, so the registry is still
trusted for the first run (and for the ID it reports: a malicious registry can
lie). A registry that does not send an owner ID is not pinned, and capm warns
about it. Deleting `known.json` or running `capm known forget` removes the
pin. Local-directory runs are never pinned. Still pin exact versions
(`login/name@1.2.3`) and review `capm inspect`.

## Permission diff on upgrade

`capm run` also records the version, digest and manifest of the last registry
version you confirmed. Running a different version shows what changed in egress
hosts, mounts (path and mode), secrets, MCP servers (name, URL, secret), base
agent and context files before the normal confirmation. Anything added, a mount
going from read-only to read-write, a re-pointed MCP server or a different base
agent counts as an escalation: `--yes` alone then does not skip the prompt, and
non-interactive use needs `--accept-permission-changes`. Removed-only changes
are informational, and downgrades are diffed the same way. If the registry
serves different bytes for a version you already ran (versions are meant to be
immutable), the run is refused unless `--accept-changed-digest` is given.
`capm inspect owner/name@v --diff [oldversion]` prints the diff without running.

Limits: the diff compares declared manifests only, so it says nothing about
changes to the contents of context files or other bundle files, and the
baseline is whatever you last confirmed on this machine; the first run of a
bundle has nothing to compare with.

## Tokens

Registry tokens issued by `capm login` expire after 90 days by default
(`TOKEN_TTL_DAYS` on the server; 0 means never). Tokens issued before expiry
existed were given an expiry of 90 days from the deploy that introduced it. An
expired token is refused with the same `401` as an unknown one.

The registry stores only the sha256 hash of each token, never the token, so it
cannot show you a token again and a database leak does not reveal usable
tokens. Each token has an id, an optional name (`capm login` uses the machine's
hostname), a last-used date (updated at most hourly) and an expiry. Rows for
revoked and expired tokens are kept for 30 days for the audit trail, then
deleted.

Tokens are stored in plain JSON (mode 0600) in your user config directory.
You can end them yourself:

- `capm logout` revokes this machine's token on the registry and deletes the
  local credentials. If the registry cannot be reached (or is an older version
  without revocation), the credentials are still deleted locally, capm says so,
  and the token stays valid on the server until it expires.
- `capm tokens` lists your tokens (current one marked `*`); `capm tokens revoke
  <id>` revokes one, for example for a laptop you lost.
- An admin can revoke all of a user's tokens with `capm admin revoke-tokens`.

capm warns on stderr when the stored token has under 7 days left. Revocation
and expiry apply to the token itself; the next `capm login` issues a fresh one.

## sbx runtime behaviour is unverified

Nothing in `capm run` has been exercised against a real sandbox: sbx needs a
Docker login that was not available while capm v1 was built. Every sbx
command, flag, output format and policy behaviour capm relies on comes from
`sbx --help` (v0.48), the Kit v3 spec and Docker's docs. capm fails closed
where it can (for example, the MCP check aborts if it cannot parse
`sbx mcp inspect --json`), but it may fail outright, or behave differently
from what is described here, on a real machine.

[sbx-findings.md](sbx-findings.md) lists the verification steps that are
still open:

- **V0** a pinned kit reference (`docker.io/docker/sbx-kit-claude:<version>`)
  launches and reports that agent version.
- **V1** MCP registration: `sbx mcp add` with headers, then `sbx mcp inspect`
  (capm also needs its JSON shape, and the output of
  `sbx secret ls --global --quiet`).
- **V2** a pinned base, a generated v3 mixin and capm's flags compose in one
  `sbx create`, and whether `--sandbox` secrets and policy can be set before
  the sandbox exists.
- **V3** where mounts appear inside the sandbox.
- **V4** read-only mounts are really read-only.
- **V5** egress: what a deny-all baseline blocks, whether a mixin alone can
  narrow egress, whether the base agent's hosts are reachable, and what
  `sbx policy ls` prints. Until V5 passes, egress stays NOT enforced.
- **V6** secrets: the sandbox sees placeholders, not values; how a model key
  and a global `anthropic` secret interact.
- **V7** context files land where the agent reads them.
- **V8** the sandbox cannot reach an MCP host directly; the agent talks only
  to the gateway.

Also unverified: the `--skills off` spelling's effect, cleanup of capm's
per-run sbx secrets and MCP registrations (a killed `capm run` can leave
`capm-*` registrations behind; remove them with `sbx mcp rm` and
`sbx secret rm`).

## Yank is advisory; removal and bans are the takedown

A yank is the owner's "please don't use this". It is **not** a takedown: it
only hides the version from `latest` and adds a warning, and anyone who asks
for the exact version still gets it. That is deliberate, so an owner cannot
break people who pinned a version. Do not treat a yanked bundle as safe, and do
not expect yank to remove anything.

Registry admins (GitHub numeric ids in `ADMIN_GITHUB_IDS`) have two stronger
tools, used through `capm admin` (runbook in
[self-hosting.md](self-hosting.md)):

- **Removal** of a version or a whole bundle. The registry answers `410 Gone`
  with the admin's reason to downloads, metadata and exact-version resolves;
  `capm pull`, `inspect` and `run` refuse and print the reason. Removed
  versions are never `latest`, their manifest is withheld, the data is deleted
  from the server (unless a live version shares the same bytes), and the
  version number can never be published again. The reason is written by an
  admin but is still untrusted text to clients, so the CLI and website
  sanitise it like any registry string.
- **Bans** of a user. A banned user's tokens stop working (they are not deleted,
  so they work again after an unban; use `capm admin revoke-tokens` as well for
  a permanent cut-off), they cannot get a new
  one, and their bundles disappear from listings and answer 404. A ban is per
  GitHub account, not per person.

What these do not do: removed data remains in backup snapshots until they age
out (urgent purge: `restic forget --prune`), copies people already pulled are
unaffected, and nothing stops a removed file being republished under a new
version number or another account (a new publish is not blocked by content).
Every admin action is recorded in an audit log (`capm admin log`). The admin
API answers 404 to everyone who is not an admin.

## Quotas are the disk-fill defence

The registry's volume does not enforce its size, so anyone with a GitHub
account could otherwise fill it by publishing. Per-user limits (100 MiB, 50
bundles, 200 versions per bundle by default) are checked inside the publish
transaction, so concurrent uploads cannot slip past them, and a registry-wide
cap (3 GiB) makes publishes fail with 507 before the disk is full. They bound a
single account, not an attacker: many accounts can still add up, which is what
the global stop is for, and it also stops honest users at that point. The
limits do not cover a flood of rejected requests (a quota rejection still uses
the user's hourly publish allowance, and per-IP limits apply only to login
routes), nor the cost of the data in backups. Removed versions free their share
once the blob is deleted; yanked ones do not.

## The public deployment

The registry at `https://capm.masondrake.dev` is open to the internet, and
anyone with a GitHub account can publish. That sharpens several of the points
above. Operating procedures are in [self-hosting.md](self-hosting.md).

- **A leaked token is valid until it is revoked or expires (90 days).** Owners
  can revoke their own tokens (`capm tokens revoke`, `capm logout`) and admins
  can revoke all of a user's tokens, but a stolen token is usable until someone
  notices. Admins can also remove versions and ban users (next section), but
  banning does not keep the person out for good, since any GitHub account can
  log in again. Treat every bundle from an unknown publisher as untrusted;
  yanking does not stop pulls of an exact version.
- **`CLIENT_IP_HEADER` is trusted blindly.** If set (for example to
  `CF-Connecting-IP`), the backend rate-limits on whatever IP that header
  holds, with no check on who sent it. It is safe only if every request
  reaches the backend through the proxy that sets the header. Cloudflare does
  set it, but anyone who can reach Traefik directly on the LAN
  (`10.0.10.19:80`) with the right `Host` header can send the header
  themselves and pick any IP, evading the per-IP auth limits. A missing or
  malformed value falls back to the `X-Forwarded-For` logic, so only a
  well-formed spoofed IP works. Leave it unset unless a header check showed
  the default logic puts all visitors in one bucket.
- **Backups hold everything.** Nightly snapshots in R2 contain the full
  database, including token hashes. They are encrypted with the restic
  password, which is not stored in the cluster in plain form; keep it
  elsewhere. Removing a bundle from the live registry does not remove it from
  old snapshots.
