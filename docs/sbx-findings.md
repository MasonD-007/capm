# sbx feasibility findings (Task 0)

Tested against `sbx v0.48.0` (macOS, installed at `/opt/homebrew/bin/sbx`; v0.49.1 exists), 2026-10-20.

**Nothing below was run in a real sandbox.** sbx needs a Docker login before it creates one; see "Verification limit" near the end. Every answer is from CLI help, the Kit v3 spec or docs, and is marked unverified (docs only).

## Manifest and `inspect` changes required (read before Task 1)

Nothing is "not supported", but several answers differ from the working assumptions, and everything runtime-related is unverified. Changes, in order of importance:

1. **MCP traffic does not originate in the sandbox.** The gateway runs on the host and the agent only connects to it. The design rule "an MCP URL's domain is automatically part of the enforced egress list" would therefore be wrong if read as "sandbox egress". Change `inspect` to show MCP URLs in their own line, "reached through the sbx MCP gateway on your machine (host-side, not sandbox egress)", plus the secret name. Do not add MCP hosts to the sandbox egress allowlist, if verified (verify step V8) that the agent only talks to the gateway; otherwise keep them in both lists. **This touches the Global Constraint "there is no hidden network access / MCP URLs must appear in the egress list": it is still satisfied (nothing is hidden) but the wording of the constraint and the egress-list placement change. Per Task 0 Step 3 this needs a user decision before Task 1.**
2. **Exact-hostname enforcement depends on the baseline.** `inspect` must not claim "the sandbox can reach only these hosts" unless capm run enforces it. Options: (a) `capm run` generates a v3 mixin kit with `network-policy@2` and aborts if the effective policy (`sbx policy ls NAME`) contains anything wider than the manifest plus the base agent's own hosts; or (b) `capm run` requires `sbx policy init deny-all` as a precondition. The manifest keeps `network.egress: [exact-host]`. Remove wildcards (already out of scope for v1). Port is fixed to 443.
3. **Base agent hosts must be listed.** The built-in claude kit allows api.anthropic.com, platform.claude.com, downloads.claude.ai, claude.com, mcp-proxy.anthropic.com, bridge.claudeusercontent.com (all :443); opencode adds a broad multi-provider list. `inspect` should print "base agent (sbx) egress" separately from "bundle egress" and from "model endpoint (supplied by you)". capm should not let a bundle claim the base agent's hosts as its own.
4. **Mounts: manifest declares logical name + mode only.** Container path: **unverified assumption** that sbx chooses it (the CLI help does not say whether the in-sandbox path mirrors the host path; verify step V3). The host path comes from the installer at `run`. Schema: `mounts: [{name, mode: ro|rw, description}]`, no host path, no target path. Do not promise a fixed in-sandbox path until V3 shows what it is.
5. **Secrets: manifest `secrets` entries need a binding type.** sbx only has fixed service names plus experimental `set-custom` (env var + host binding). Manifest secret = `{name, description, env: NAME}` and `capm run` binds it with `set-custom --sandbox`. MCP bearer secrets map to `mcp:<server>:<name>` instead. These are global-store names unless `--sandbox` scoped (set-custom supports it; MCP secrets are global, so namespace them as `capm-<bundle>-<name>` to avoid cross-bundle collision). Custom secrets are experimental: say so in the docs.
6. **Base agent pin = OCI kit ref.** Manifest `agent: {name: claude|opencode, version: x.y.z}`. `capm run` maps to `docker.io/docker/sbx-kit-<name>:<version>`; reject versions not in the published tag list (claude 2.1.267-2.1.296 subset, see answer 5 in the table below; opencode 1.18.31, 1.18.33). Mapping is open question #3 from the spec ("how a version pin maps to sbx's agent images"): answered. Requires sbx >= 0.45 and network access to docker.io at first run.
7. **Model endpoint for OpenCode is a file, not an env var.** For OpenCode, `capm run` has to write an `opencode.json` provider block; for Claude, `ANTHROPIC_BASE_URL` via `-e`. Keep "model endpoint supplied by you" as a separate `inspect` line and add its host to the per-sandbox allow rule at run time only.
8. **Context files can carry config the sandbox honours.** Because context is delivered via kit `agent-context`/skills, `inspect` must keep the prompt-injection caveat already in the design, and list the destination paths from answer 6 in the table below.
9. **Pin and mixin compose via one command (unverified).** See "Composed `capm run` sequence" below; Task 7 must be written against that sequence, and V0/V2 must pass before it is final.


## Answers

| # | Question | Answer | Evidence | Exact command / config |
|---|---|---|---|---|
| 1 | Per-sandbox egress limited to exact hostnames | **Supported, with a catch.** Rules can be added per sandbox and accept exact `host[:port]`. But sbx's default policy is a broad allowlist (wildcards such as `*.googleapis.com`), and a per-sandbox allow only *adds* to it. A true "only these hosts" sandbox needs either a deny-all global baseline, or a generated kit that declares `network-policy`. Unverified (docs only). | `[CLI]` `[DOCS]` `[SPEC]` | `sbx policy init deny-all` (global, one-time) then `sbx policy allow network --sandbox NAME "api.example.com:443"`; or `sbx create docker.io/docker/sbx-kit-claude:<ver> --kit ./capm-mixin` (pinned base plus mixin; see composed sequence) with `network-policy@2` `runtime.allow: [api.example.com:443]`. Narrowing only: `sbx create --deny-network HOST`. Inspect: `sbx policy ls NAME`. |
| 2 | Host dir mounted read-only vs read-write | **Supported.** First path is the read-write workspace; extra paths take a `:ro` suffix; a single file may be `:ro`. Unverified (docs only). Container path is chosen by sbx, not by the bundle. | `[CLI]` | `sbx create docker.io/docker/sbx-kit-claude:<ver> /work/rw /data/docs:ro` |
| 3 | Secret storage, injection, referencing by name | **Supported, but not as free-form names.** Host-side store; the proxy injects the real value into outbound requests and the sandbox only sees a placeholder. Built-in services are a fixed list (anthropic, openai, github, google, groq, mistral, nebius, openrouter, xai, ...). Arbitrary names use `set-custom` (experimental), which binds one secret to an env var plus host(s). Unverified (docs only). | `[CLI]` `[DOCS]` | `printf %s "$VAL" \| sbx secret set anthropic --sandbox NAME`; custom: `sbx secret set-custom --sandbox NAME --host api.example.com --env MY_KEY --command 'cat /path/to/secret'` (flags: `--host`, `--env`, `--value` or `--command`, `--sandbox`; `--value` lands in shell history, prefer `--command`). Remove: `sbx secret rm`. |
| 4 | Claude Code / OpenCode pointed at installer-supplied model URL and key | **Likely supported, unverified.** `-e KEY=VALUE` sets sandbox env at create. Claude Code reads `ANTHROPIC_BASE_URL`; the key can be a `set-custom` placeholder bound to the model host. The model host must also be allowed by egress policy. Interaction with the built-in `anthropic` service secret: that secret is injected by the proxy only for api.anthropic.com (x-api-key) and mcp-proxy.anthropic.com. A `set-custom --host models.example.com` rule matches a different host, so the two should not collide, but if the installer's model host IS api.anthropic.com (or a wildcard covering it) both rules compete for the same request and which wins is unknown; capm should refuse that case or require that no `anthropic` secret is stored. Unverified, step V6. OpenCode has no documented base-URL env var in sbx docs; it reads project-level `opencode.json` from the workspace, so the provider `baseURL` has to go there. Unverified (docs only). | `[CLI]` `[SPEC]` | Claude: `sbx secret set-custom --sandbox NAME --host models.example.com --env ANTHROPIC_API_KEY --command 'cat /path/key'`; `sbx policy allow network --sandbox NAME models.example.com:443`; `sbx create docker.io/docker/sbx-kit-claude:<ver> . -e ANTHROPIC_BASE_URL=https://models.example.com --name NAME`. OpenCode: write `opencode.json` provider `options.baseURL` into the workspace, same secret/policy steps. |
| 5 | Agent versions; pinning | **Supported for Claude Code and OpenCode via kit refs; not via built-in names.** Built-in `claude`/`opencode` select sbx's bundled (v2) kit and cannot be pinned. v3 workload kits take a `version` arg. Published tags `[HUB]`: `docker/sbx-kit-claude`: 2.1.267, 2.1.273, 2.1.274, 2.1.278, 2.1.285, 2.1.288, 2.1.289, 2.1.291, 2.1.292, 2.1.296 (+ `latest`, 1.0.0). `docker/sbx-kit-opencode`: 1.18.31, 1.18.33 (+ `latest`). | `[HUB]` `[SPEC]` `[DOCS]` | `sbx run docker.io/docker/sbx-kit-claude:2.1.267 .` ; `sbx run docker.io/docker/sbx-kit-opencode:1.18.33 .` ; arg override: `--kit-arg version=2.1.292`. Needs sbx >= 0.45. |
| 6 | Context files (prompts, skills) available to the agent | **Supported.** Two routes. (a) Generated mixin kit: `agent-context@2` (inline text) for instructions and `agent-skill@1` (singular) for one bundled skill directory (the mixin ships it in its image; the base kit already declares the plural `agent-skills@1`, which is the *destination* path the agent scans, so the capm mixin should use only the singular `agent-skill@1`). (b) Without building a kit: `sbx cp` into the sandbox after create. Targets: Claude `~/.claude/CLAUDE.md` and `~/.claude/skills/<name>/SKILL.md`; OpenCode `~/.config/opencode/AGENTS.md` and `~/.config/opencode/skills/<name>/`. Host `~/.claude` is NOT visible in the sandbox (project-level config in the workspace only). Unverified (docs only). | `[SPEC]` `[CLI]` `[DOCS]` | Kit: `capabilities: [{type: com.docker.sandbox/agent-context@2, config: {filename: CLAUDE.md, directory: /home/agent/.claude, content: "..."}}, {type: com.docker.sandbox/agent-skill@1, config: {path: /opt/capm/skills/foo}}]`. Cp: `sbx create docker.io/docker/sbx-kit-claude:<ver> . --name N && sbx cp ./ctx/CLAUDE.md N:/home/agent/.claude/ && sbx cp ./ctx/skills/my-skill N:/home/agent/.claude/skills/` (copy each skill directory individually, under a name that does not collide with a host-store skill) (the skills dir itself stays writable, so `sbx cp` of a new skill directory into it should work; only the entries linked from the shared host skills store are read-only, so cp must not target a name that collides with a store skill. Unverified, step V7). Project-level fallback: `CLAUDE.md` / `AGENTS.md` in the workspace. |
| 7 | Remote MCP servers and bearer tokens, per agent | **Supported, with a different network model.** `sbx mcp add NAME --url https://...` registers on the host; every sandbox runs an MCP gateway and the sbx claude and opencode kits register that gateway with the agent automatically. Bearer: header template with a secret placeholder, value stored as `mcp:NAME:KEY`. The agent talks only to the gateway, not to the MCP host. Unverified (docs only). | `[DOCS]` `[CLI]` `[SPEC]` | `sbx mcp add acme --url https://mcp.acme.com/mcp --skip-auth --header 'Authorization: Bearer ${api-key}'` ; `printf %s "$TOKEN" \| sbx secret set mcp:acme:api-key` ; `sbx create docker.io/docker/sbx-kit-claude:<ver> . --static-mcp acme --name N`. Check: `sbx mcp inspect acme`. Restart sandbox/sandboxd after changing the secret. |

## Composed `capm run` sequence (pin + mixin + env + MCP + context; unverified)

Task 7 combines every piece. Unverified assumption: `sbx create` accepts a kit reference (the pinned v3 workload) as its first argument together with `--kit` (a mixin) and the ordinary flags `-e`, `--static-mcp`, positional workspaces. The help text supports each flag individually (`sbx create AGENT|SANDBOX_KIT [PATH...]`, `--kit` "must be a mixin"), and the docs show `sbx run <kit-ref> --kit <mixin>`, but I found no example combining all of them. The docs also say "Built-in names like `claude` select v2 kits" and "every kit in a v3 sandbox must be v3", so the generated mixin must be v3 (`schemaVersion: "3"`, `kind: mixin`, built with `sbx kit pack`, which expects `spec.yaml` plus optional `files/`). Open question: does that v3 mixin also work on the v2 built-in `claude`? If not, pinned-ref is the only route.

```sh
N=capm-acme-1                                  # unique sandbox name
BASE=docker.io/docker/sbx-kit-claude:2.1.292   # from manifest agent.version
# 1. generate ./capm-mixin/spec.yaml (v3 mixin): network-policy@2 runtime.allow = bundle egress only,
#    agent-context@2 (CLAUDE.md), agent-skill@1 entries; then:
sbx kit pack ./capm-mixin -o /tmp/$N-mixin.zip
# 2. secrets, scoped to this sandbox
install -m 600 /dev/null /tmp/$N.key && printf %s "$MODEL_KEY" > /tmp/$N.key   # 0600 file outside any mounted workspace
sbx secret set-custom --sandbox $N --host models.example.com --env ANTHROPIC_API_KEY --command "cat /tmp/$N.key"   # remove the file after the run
# 3. MCP (host-side registry + secret)
sbx mcp add acme --url https://mcp.acme.com/mcp --skip-auth --header 'Authorization: Bearer ${api-key}'
printf %s "$MCP_TOKEN" | sbx secret set mcp:acme:api-key
# 4. network: per-sandbox allow for the model host (global baseline already deny-all)
sbx policy allow network --sandbox $N models.example.com:443
# 5. create: pinned base + mixin + env + MCP + mounts (rw workspace first, extras :ro)
sbx create "$BASE" /work/rw /data/docs:ro --kit /tmp/$N-mixin.zip \
    -e ANTHROPIC_BASE_URL=https://models.example.com --static-mcp acme --name $N
# 6. context not covered by the mixin
sbx cp ./ctx/extra-skill $N:/home/agent/.claude/skills/
# 7. launch
sbx run --name $N
```

Ordering problem to check (V2): `--sandbox $N` secrets and policy rules in steps 2 and 4 reference a sandbox that does not exist until step 5. Either `sbx create` must come first (then steps 2/4 apply and the sandbox is restarted), or global-scoped secrets/rules must be used. If the sandbox must exist first, move step 5 before 2 and 4 and `sbx stop`/restart after. Treat the order above as unverified. Possible resolution (V2 variant): `sbx kit add $N /tmp/$N-mixin.zip` (experimental, "add a mixin to an existing sandbox", recreates the container) lets capm create the pinned base sandbox first, set `--sandbox` secrets and policy, then add the generated mixin. That needs the sandbox to carry the recreate-aware label; unverified.

## Verification limit

`sbx` requires `sbx login` (a Docker account) before the daemon will start or any sandbox can be created (`sbx ls`, `sbx policy ls`, `sbx kit inspect` all return `error: not signed in to Docker`). I did not sign in. So **no sandbox was created and none of the answers above was proven by running a sandbox.** What was verified:

- `[CLI]` flag and subcommand existence and semantics, read from `sbx ... --help` on the installed binary.
- `[SPEC]` the Docker Sandbox Kit v3 spec and the shipped claude/opencode kit sources (github.com/docker/sandbox-kit-spec).
- `[HUB]` published kit tags, queried live from Docker Hub.
- `[DOCS]` pages under https://docs.docker.com/ai/sandboxes/.

Everything is marked "unverified (docs only)" in the table. Re-run the "To verify" script once someone with a Docker login can do it (about 15 minutes, commands below). No sandboxes or other resources were created, so there is nothing to clean up.

## To verify (needs `sbx login`; do before freezing the schema)

**Warning: `sbx policy init deny-all` and `sbx policy reset` change the global network policy for every sandbox on this machine, not just the test one.** Note the current state first (`sbx policy ls > /tmp/policy-before.txt`), run the egress steps, then restore with the cleanup block. `policy init` is one-time per the help text; `sbx policy reset` clears all policies and lets you re-init (`balanced` is the usual default; choose what `policy-before.txt` shows). Do this on a throwaway machine or accept that your other sandboxes lose their rules until restored.

```sh
sbx login && sbx daemon start
sbx policy ls | tee /tmp/policy-before.txt      # record the current policy
mkdir -p /tmp/ro /tmp/rw /tmp/ctx && echo x > /tmp/ro/f

# V0 pinned base launch (Q5)
sbx kit inspect docker.io/docker/sbx-kit-claude:2.1.292
sbx create docker.io/docker/sbx-kit-claude:2.1.292 /tmp/rw --name pin1
sbx exec pin1 claude --version                  # expect 2.1.292

# V1 MCP registration first: --static-mcp takes names ALREADY registered with `sbx mcp add`
sbx mcp add t --url https://mcp.example.net/mcp --skip-auth --header 'Authorization: Bearer ${k}'
printf %s dummy | sbx secret set mcp:t:k && sbx mcp inspect t

# V2 pinned base + generated v3 mixin + flags (the Task 7 composition)
#   build /tmp/capm-mixin/spec.yaml with network-policy@2 runtime.allow [example.com:443] and agent-context@2
sbx kit validate /tmp/capm-mixin && sbx kit pack /tmp/capm-mixin -o /tmp/mixin.zip
sbx create docker.io/docker/sbx-kit-claude:2.1.292 /tmp/rw /tmp/ro:ro --kit /tmp/mixin.zip \
    -e ANTHROPIC_BASE_URL=https://example.com --static-mcp t --name spike
#   record: does it accept the combination? does the mixin work on the built-in `claude` too?
#   record: can secrets/policy for --sandbox spike be set before create, or only after?
#   Variant (ordering): create the pinned base alone, then add the mixin afterwards:
sbx create docker.io/docker/sbx-kit-claude:2.1.292 /tmp/rw --name spike2 --static-mcp t
sbx kit add spike2 /tmp/mixin.zip               # does it recreate cleanly and keep --sandbox secrets/policy?

# V3 where do the mounts appear inside? (path may differ from host path)
sbx exec spike sh -c 'mount | grep -E "ro|rw" | head; pwd; ls /tmp/ro /tmp/rw'
# V4 read-only vs read-write (Q2), using the paths found in V3
echo x > /tmp/ro/f
sbx exec spike sh -c 'touch /tmp/ro/f2'         # expect read-only failure (adjust path per V3)
sbx exec spike sh -c 'touch /tmp/rw/f2'         # expect success

# V5 egress (Q1) -- the central claim; tests BLOCK, not only allow
sbx exec spike sh -c 'curl -sS -m5 -o /dev/null -w "%{http_code}\n" https://example.org'   # baseline under default policy
#   `sbx policy init` is a one-time step that must run before the first sandbox, so on a machine that already
#   ran sandboxes the normal path is: sbx policy reset && sbx policy init deny-all  (GLOBAL; see warning above)
sbx policy reset && sbx policy init deny-all
sbx exec spike sh -c 'curl -sS -m5 https://example.org'        # expect blocked
sbx policy allow network --sandbox spike example.com:443
sbx exec spike sh -c 'curl -sS -m5 -o /dev/null -w "%{http_code}\n" https://example.com'   # expect 200
sbx exec spike sh -c 'curl -sS -m5 https://example.org'        # still expect blocked
sbx exec spike sh -c 'curl -sS -m5 https://www.example.com'    # exact host: expect blocked
sbx exec spike sh -c 'curl -sS -m5 https://api.anthropic.com'  # base agent host: allowed or not? record
sbx policy ls spike                                             # does it list mixin-declared rules?
#   Repeat the block/allow test WITHOUT the global deny-all but with the mixin's network-policy@2:
#   does a non-listed host get blocked? (decides whether the mixin alone can enforce exact egress)

# V6 secrets / model base URL (Q3, Q4)
sbx secret set-custom --sandbox spike --host example.com --env DUMMY_KEY --value dummy123
sbx exec spike sh -c 'echo $DUMMY_KEY'          # expect a placeholder, not dummy123
sbx exec spike sh -c 'env | grep ANTHROPIC'     # ANTHROPIC_BASE_URL present? key a placeholder?
printf %s dummy-anthropic | sbx secret set anthropic --sandbox spike   # then repeat with the model host == api.anthropic.com to see which rule wins

# V7 context (Q6)
sbx cp /tmp/ctx spike:/home/agent/ctx
sbx cp /tmp/ctx spike:/home/agent/.claude/skills/        # writable alongside store links?
sbx exec spike sh -c 'ls -la /home/agent/.claude/ /home/agent/.claude/skills; cat /home/agent/.claude/CLAUDE.md'

# V8 MCP gateway-only (Q7): mcp.example.net is in NO allow list (the mixin and V5 only allow example.com)
sbx exec spike sh -c 'curl -sS -m5 https://mcp.example.net/mcp'   # expect blocked: sandbox cannot reach the MCP host directly
sbx exec spike sh -c 'env | grep -i MCP'                          # gateway URL present? (agent talks only to it)

# CLEANUP / RESTORE
sbx rm spike spike2 pin1; sbx mcp rm t; sbx secret rm mcp:t:k; sbx secret rm anthropic --sandbox spike 2>/dev/null
sbx policy ls                                   # compare with /tmp/policy-before.txt
sbx policy reset && sbx policy init balanced    # restore global policy (use what policy-before.txt showed); re-add any custom rules from that file
```

## Sources

- https://docs.docker.com/ai/sandboxes/ (security, mcp-gateway, agents/claude-code, agents/opencode, customize)
- https://github.com/docker/sandbox-kit-spec : `docs/spec/SPEC-v3.md`, capabilities `network-policy@2`, `credential@1`, `host-mount@1`, `agent-context@2`, `agent-skills@1`, `agent-skill@1`, `docs/agent-context-placement.md`, `examples/claude/claude.yaml`, `examples/opencode/opencode.yaml`
- Docker Hub tags: hub.docker.com/r/docker/sbx-kit-claude, hub.docker.com/r/docker/sbx-kit-opencode
