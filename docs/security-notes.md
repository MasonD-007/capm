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
(new versions; existing versions are immutable). The CLI pins nothing: it
does not remember who published a bundle you ran before. Pin exact versions
(`login/name@1.2.3`) and review `capm inspect` every time, especially after
a new version appears.

## Tokens

Registry tokens issued by `capm login` have no expiry and cannot be revoked
yet. They are stored in plain JSON (mode 0600) in your user config directory.
Delete the credentials file to log out locally; the token itself stays valid
on the server.

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

## The public deployment

The registry at `https://capm.masondrake.dev` is open to the internet, and
anyone with a GitHub account can publish. That sharpens several of the points
above. Operating procedures are in [self-hosting.md](self-hosting.md).

- **Tokens cannot be revoked, and that matters more here.** A leaked token
  stays valid forever, and there are no admin endpoints to remove a malicious
  bundle or ban a publisher. The only remedy is the takedown runbook in
  [self-hosting.md](self-hosting.md): stop the backend and edit the SQLite
  database by hand (yank or delete a version, delete a user's tokens). Deleting
  tokens does not keep the person out, since any GitHub account can log in
  again. Treat every bundle from an unknown publisher as untrusted; yanking
  does not stop pulls of an exact version.
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
