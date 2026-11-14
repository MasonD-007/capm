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

## README text on the website is untrusted

A bundle's root `README.md` is shown on its web page below everything derived
from the manifest, under a heading that says it is from the author and
unverified. The registry stores it at publish time (64 KiB cap, invalid UTF-8
replaced) and the website renders it as Markdown with these rules:

- Raw HTML is never rendered: `<script>`, `<iframe>`, inline styles and event
  handlers appear as plain text.
- Links keep only `http:`, `https:` and `mailto:` destinations, and carry
  `rel="nofollow noopener noreferrer"`. `javascript:`, `data:`, relative and
  other links lose their destination and show as text.
- Images are never loaded (no tracking pixels, no remote content); each is
  shown as a text link to the image URL.
- Headings are demoted so a README cannot pose as a page section, and control
  and bidirectional-override characters are replaced.

A README can still lie, and its links can point anywhere. The CLI does not
print it. Removed versions serve no README, and the versions list endpoint
never includes README bodies.

## No signing; identity is a GitHub login

Bundles are not signed in v1. `capm pull` checks the download against the
sha256 digest the registry reports, which protects against corruption in
transit, not against a malicious or compromised registry. The only publisher
identity is the GitHub login in the bundle name (`login/name`).

The registry can now store one signature (a Sigstore bundle) per version, which
an authorised publisher uploads from CI; it is write-once, and the registry
only stores and serves it. It does not verify it and its word is not trusted:
a version marked `signed` only means a signature file exists. Verification
happens in the CLI, which is not wired up yet.

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

## What the risk labels mean

Risk labels say how much a bundle declares it can touch. They are computed
deterministically from the manifest (`manifest/risk.go`), so the CLI, the
registry and the website agree. `capm inspect` and `capm run` recompute them
locally from the manifest they validated and never use the registry's copy;
the website and the `!!` / `!` marker in `capm list` and `capm search` show
the registry's claim.

- **Labels are derived from what the bundle declares.** They are not a review
  of the bundle, its prompts or its code, and say nothing about intent.
- **Declared is not enforced in v1** (see the first section). A label about
  egress or mounts describes the declaration, not a guarantee.
- **The absence of labels is not an endorsement.** A bundle with no labels
  still runs an agent with a model, a sandbox and whatever it declares. Where
  no label applies, capm says "no risk labels apply; this is not an
  endorsement" (CLI and website) and the list marker is blank, which also
  covers an info-only bundle and a registry that does not report risk.

Counts use distinct egress hosts. Validation already rejects wildcard hosts
and absolute or `..` mount paths, so there are no rules for them; a mount of
`.` (or anything that cleans to it, such as `./` or `a/..`) is the workspace
root. A secret named by an MCP server goes only to that server; every other
declared secret is offered to every host in the egress list.

| ID | Severity | Fires when | Reason form |
| --- | --- | --- | --- |
| `egress_many_hosts` | high | more than 10 distinct egress hosts | `Declares N egress hosts (more than 10)` |
| `mount_read_write` | high | any mount has mode `read-write` | `Mounts read-write (N): paths` |
| `mount_workspace_root` | high | any mount path cleans to `.` (either mode) | `Mounts the workspace root (N): path (mode), ...` |
| `secret_many_hosts` | high | a declared secret that no MCP server names, and more than 3 distinct egress hosts | `Secrets offered to every egress host (N secrets, M hosts): names` |
| `base_egress_broad` | caution | the base agent's kit allows a broad host list capm does not enumerate (OpenCode) | `Base agent opencode allows a broad host list that capm does not enumerate` |
| `context_files` | caution | any context file | `Reads context files (N): paths` |
| `mcp_servers` | caution | any MCP server | `Uses MCP servers (N): name (host), ...` |
| `secrets_declared` | caution | any declared secret | `Declares secrets (N): names` |
| `egress_none` | info | no egress host declared (the base agent's own hosts still apply) | `Declares egress hosts (0)` |
| `mounts_read_only` | info | at least one mount and all are `read-only` | `Mounts are all read-only (N): paths` |

Labels are listed high, then caution, then info, then by ID. The `risk` field
the registry sends is the highest severity present. `capm list` and `capm
search` show `!!` for high and `!` for caution; those columns are the
registry's claim, so use `capm inspect` for the locally computed labels.

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

## Publishing from GitHub Actions (OIDC)

A workflow can exchange its GitHub OIDC token at `POST /v1/auth/oidc` for a
registry token and publish with it (see "Publish from GitHub Actions" in the
getting-started guide).

**What a successful exchange proves.** GitHub signed (RS256, key from GitHub's
JWKS) a token saying that a workflow in a repository owned by the GitHub user
with id `repository_owner_id` is running, in response to an event other than a
pull request, and asked for a token for this registry's audience. The registry
then treats the publish as coming from that GitHub user, the same account a
`capm login` by that user would be.

**What it does not prove.**

- Who triggered the run. Anyone who can make the workflow run (push access, or
  a `workflow_dispatch`) causes a publish as the owner.
- That the published bundle matches the repository's contents. The workflow
  packs whatever is in its working directory; a step can alter it.
- That the repository, the workflow or the Actions it uses are trustworthy.
  Anyone with write access to a repository owned by the user, and any Action
  that repository's workflows run (including third-party Actions and their
  dependencies), can publish as that user. Pin Actions to commit SHAs and treat
  write access to the repository like the publisher's password.
- Nothing about the bundle's safety. `publishedVia` on a version
  (`repository`, `workflowRef`, `sha`) is provenance recorded from a verified
  token; it is not a "verified publisher" mark and the registry does not use it
  to rank or approve anything. Anyone can also publish by hand under their own
  login.

**What the registry refuses.** Tokens that are not RS256 or have no `kid`;
signatures that do not verify against keys fetched from the configured issuer
(`OIDC_ISSUER`, default `https://token.actions.githubusercontent.com`; the keys
URL is configured, never taken from the token); an `iss` or `aud` that is not
exactly the configured values (an `aud` array is accepted only with that single
element); expired tokens, tokens not yet valid, or lived longer than an hour
(60 second clock skew); a missing `jti`. A `repository` that does not belong to
`repository_owner`. **Pull request events:** any `event_name` starting with
`pull_request` is refused, because a pull request, a fork's included, must not
be able to publish. For `pull_request_target` GitHub's `ref` and `sub` claims
look exactly like a push to the base branch, so `event_name` is the only signal.
GitHub's claims do not say whether the owner is a user or an organisation, so
the registry asks GitHub's API (`GET /user/<id>`, unauthenticated, cached for 2
minutes); if that lookup fails, the exchange fails (503). Only the types `User`
and `Organization` are accepted; an organisation is handled as described in
[Organisation namespaces](#organisation-namespaces). Banned accounts (users or
organisations) are refused as at login.

**The minted token.** It has scope `publish` and a fixed 15 minute lifetime
(not `TOKEN_TTL_DAYS`), is not renewable, and is named `ci:<repository>`. It can
call exactly one route, `PUT /v1/bundles/{owner}/{name}/{version}`, and only for
the one account it was minted for (the repository owner's id): never for the
person who triggered the run, never for another organisation, and a token for a
user's repository cannot publish into an organisation that user belongs to. Every other authenticated route (yank, token management, usage, `me`,
admin) answers it 403, and a route added later is closed to it by default.
Quotas, publish rate limits, duplicate and validation checks apply as to any
publish. The owner sees these tokens in `capm tokens` and can revoke them; an
account may hold at most 20 live CI tokens, so valid GitHub tokens (anyone can
mint one for any audience) cannot flood the table.

**Replay.** Each accepted `jti` is remembered in memory until the ID token's
expiry plus the 60 second skew, so the same ID token cannot be exchanged twice
(401). The memory is a bounded set (10,000 entries); when it is full of live
entries the registry answers 503 rather than forget. It is per process: a
restart forgets it, so a token captured before a deploy can be replayed once
afterwards while it is still unexpired (at most an hour, typically minutes). An
ID token is a bearer credential: treat it like the registry token it buys.

**If GitHub's JWKS is unreachable.** Keys are cached in memory (refetched after
an hour, at most once a minute even after a failure, and an unknown `kid` only
triggers a refetch if the last attempt is over a minute old). A cached key keeps
working while the last successful fetch is under 24 hours old; past that, and
when no keys were ever fetched, exchanges fail closed with 503 and
`Retry-After`. Publishing with a normal `capm login` token is unaffected.

## Organisation namespaces

An organisation is an account row in the registry keyed by its GitHub numeric
id, with the same login handling (and the same [login reassignment](#login-reassignment)
caveats) as a user. GitHub user ids and organisation ids come from one id
space, which is why one table holds both; the registry never lets an id change
its recorded kind, and refuses and logs the attempt.

**Who may publish and yank under an organisation.** One function
(`store.AuthorizeOwner`) decides, for publish, yank, un-yank and the owner's
usage view. A caller may act under `{owner}` when:

1. they are that user (as before); or
2. the owner is an organisation, the caller is not banned, the organisation is
   not banned, and the caller has an `org_members` record, written by
   `capm login --orgs`, that is **at most 24 hours old** and has a role that may
   publish. A record without such a role, a stale record, a record dated in the
   future, or any error while looking it up all mean no; or
3. the caller is a CI token (scope `publish`) minted for exactly that account.
   A CI token never uses memberships.

**What the registry trusts to record a membership.** GitHub's answer, at login
time, to the user's own access token (kept only for the duration of that login
request, then discarded; never stored or logged):

- `GET /user/memberships/orgs?state=active` (up to 10 pages of 100): a
  membership with role `admin` (an organisation owner) qualifies.
- For a membership with role `member`, `GET /orgs/{org}`: it qualifies only if
  the reply contains `default_repository_permission` equal to `write` or
  `admin`, and the reply is about the same organisation id. If the field is
  absent (GitHub only returns it to callers with enough visibility), null, any
  other value, or the call fails, the member does **not** qualify. Fail closed.
- Write access granted by a team (rather than the organisation's base
  permission) is not looked at and does not qualify in this version.
- This has been written against GitHub's documentation and tested against a
  fake GitHub only; it has not been run against the real API. In particular,
  GitHub may well show `default_repository_permission` to few plain members, in
  which case in practice only organisation owners can publish interactively.
- An organisation row (and its membership rows) is created only for an
  organisation GitHub lists for the logging-in user and that qualifies, or by
  an OIDC exchange from a workflow of a repository the organisation owns. A
  user cannot make the registry create a row for an organisation they do not
  belong to, and nothing the client sends influences which organisations are
  listed.

**Revocation windows.** The registry only learns that someone left an
organisation, or lost write access, at their next `capm login --orgs`. Until
then their record keeps working for at most **24 hours** from the login that
recorded it. Bans take effect immediately. Revoking a CI token takes effect
immediately; the tokens last 15 minutes anyway. To stop CI publishing for an
organisation as an operator: `capm admin revoke-tokens <org>` (organisations
have no login of their own; the admin commands resolve them by login or id) or
`capm admin ban <org>` (hides its bundles too).

**What a CI token of an organisation can do.** It can publish any bundle name
under the whole organisation's namespace, from any repository of the
organisation whose workflow can request an OIDC token and is not a pull
request. Treat write access to *any* such repository (and every Action it
runs) as publish access to the organisation's namespace. Recommended: use an
organisation (or a separate one) dedicated to bundles, or restrict which
repositories may run workflows with `id-token: write`. Every version records
the repository and workflow in `publishedVia`. Nobody is recorded in
`publishedBy` for those versions.

**Members' versions.** A member publishing interactively records their id and
login as `publishedBy`, shown only for organisation bundles.

## What "published from" does and does not prove

A manifest may carry `metadata.repository` (`https://github.com/<owner>/<repo>`,
strictly validated). The registry sets `versions.repo_verified` (reported as `repositoryVerified`) only when
it was published by a CI token whose verified `repository` claim equals that
value structurally (owner and repo compared case-insensitively; not as raw
strings: a trailing slash, `.git`, another host or an extra path segment never
matches, and the manifest is refused at publish if it has one). An interactive
publish is never verified.

It proves: GitHub signed a token for a workflow in that repository, in a
non-pull-request event, and the registry issued a publish token from it for the
repository's owner.

It does not prove: that the bundle's contents match the repository's (the
workflow packs whatever its working directory holds), that the repository,
workflow or any Action it runs is trustworthy or reviewed, who triggered the
run, or that the bundle is safe. Anyone with write access to the repository
(and any Action it uses) can cause a "published from" version. The website and
`capm inspect` word it as where the version was published from, label the
registry as the source, and show an unverified repository only as the author's
claim. `capm inspect` cannot check the claim and prints nothing as published
from unless the registry's own provenance record names the same repository as
the manifest.

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

## Download counts are not a trust signal

The registry counts each successful download request per version and UTC day,
and shows totals on the website and in `capm list --sort downloads`. These are
raw, unauthenticated request counts: anyone with `curl` can inflate them, and
nothing is de-duplicated. They say nothing about whether a bundle is safe or
good, are never used for search matching, and should not be read as a
recommendation. No IP address, token or account is stored for them, only the
owner, bundle, version, day and a number.

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

## Reports are unauthenticated and can be spam

Anyone can file a report without an account (`capm report`, the form on a
bundle page, or `POST /v1/bundles/{owner}/{name}/report`). Treat reports as
leads, not evidence: they can be false, malicious, or a campaign against an
author. Reporting does not remove, hide or flag anything by itself; only an
admin's `capm admin remove` or `ban` does, and removing does not resolve the
reports, so they stay in the list until an admin resolves them.

Defences against abuse of the endpoint: 5 reports per client IP per hour, a
strict 8 KiB JSON body, a fixed list of reasons, details limited to 2000
characters with control and bidi characters stripped, and caps of 200 open
reports per bundle and 5000 overall (beyond them reports are accepted and
dropped, and an attacker learns nothing from the answer: success is always the
same `202 {}`, with no report id). These bound the table; they do not stop a
patient attacker with many addresses from burying the real reports under 5000
junk ones or from filling one bundle's 200 slots to hide a real report there.
Admins see the newest first and resolve noise in bulk by note.

What is stored about a reporter: the bundle, version, reason and text they
wrote; the time; their user id if they presented a valid token (a logged-in
CLI user; the website form is anonymous); and `reporter_key`, an HMAC-SHA256 of
their IP under a random salt generated when the backend starts and kept only in
memory. The IP itself is never stored or logged by this feature. Because the
salt changes at every restart, keys cannot be matched across restarts, and
without the running process they cannot be reversed to an address (the IPv4
space is small, so someone holding both the database and the salt could try
every address; the salt never leaves the process). The key is used only to
de-duplicate: an identical open report (same bundle, version, reason and key)
within 24 hours is not stored again. That stops accidental double submits and a
single address repeating itself; it does not stop one person using several
addresses or sending the same complaint under a different reason or version,
and a restart forgets it.
Report text is shown to admins only, and the CLI strips control and bidi
characters from it before printing.

The website form is a Next.js Server Action. Next.js rejects an action POST
whose `Origin` does not match the site's own `Host` (or `X-Forwarded-Host`),
and actions accept only POST, so another site cannot submit the form on a
visitor's behalf from a browser; `serverActions.allowedOrigins` is not set, so
only the site's own origin is allowed. A request with no `Origin` is let
through with a warning, which is a non-browser client: it could equally call the
API directly, and is rate limited the same way. The form forwards the visitor's
address from Cloudflare's `CF-Connecting-IP` (never from `X-Forwarded-For`,
which a visitor can set), so the per-IP limit applies to the visitor only while
the site is reachable solely through Cloudflare; anyone who can reach the
frontend directly (for example on the LAN) could set that header themselves.

The optional `REPORT_WEBHOOK_URL` is set by the operator, never by users, and
the notification text never contains the reporter's free text (see
[self-hosting.md](self-hosting.md#reports)).

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
