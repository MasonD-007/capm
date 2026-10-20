# sbx feasibility findings (Task 0)

Tested against `sbx v0.48.0` (macOS, installed at `/opt/homebrew/bin/sbx`; v0.49.1 exists), 2026-10-20.

**No answer below was run in a real sandbox** (sbx needs a Docker login; see "Verification limit" below the table of changes). All are CLI-help, spec or docs derived.

## Answers

| # | Question | Answer | Evidence | Exact command / config |
|---|---|---|---|---|
| 1 | Per-sandbox egress limited to exact hostnames | **Supported, with a catch.** Rules can be added per sandbox and accept exact `host[:port]`. But sbx's default policy is a broad allowlist (wildcards such as `*.googleapis.com`), and a per-sandbox allow only *adds* to it. A true "only these hosts" sandbox needs either a deny-all global baseline, or a generated kit that declares `network-policy`. Unverified (docs only). | `[CLI]` `[DOCS]` `[SPEC]` | `sbx policy init deny-all` (global, one-time) then `sbx policy allow network --sandbox NAME "api.example.com:443"`; or `sbx create claude --kit ./capm-mixin` with `network-policy@2` `runtime.allow: [api.example.com:443]`. Narrowing only: `sbx create --deny-network HOST`. Inspect: `sbx policy ls NAME`. |
| 2 | Host dir mounted read-only vs read-write | **Supported.** First path is the read-write workspace; extra paths take a `:ro` suffix; a single file may be `:ro`. Unverified (docs only). Container path is chosen by sbx, not by the bundle. | `[CLI]` | `sbx create claude /work/rw /data/docs:ro` |
| 3 | Secret storage, injection, referencing by name | **Supported, but not as free-form names.** Host-side store; the proxy injects the real value into outbound requests and the sandbox only sees a placeholder. Built-in services are a fixed list (anthropic, openai, github, google, groq, mistral, nebius, openrouter, xai, ...). Arbitrary names use `set-custom` (experimental), which binds one secret to an env var plus host(s). Unverified (docs only). | `[CLI]` `[DOCS]` | `printf %s "$VAL" \| sbx secret set anthropic --sandbox NAME`; custom: `sbx secret set-custom --sandbox NAME --host api.example.com --env MY_KEY --command 'cat /path/to/secret'` (flags: `--host`, `--env`, `--value` or `--command`, `--sandbox`; `--value` lands in shell history, prefer `--command`). Remove: `sbx secret rm`. |
| 4 | Claude Code / OpenCode pointed at installer-supplied model URL and key | **Likely supported, unverified.** `-e KEY=VALUE` sets sandbox env at create. Claude Code reads `ANTHROPIC_BASE_URL`; the key can be a `set-custom` placeholder bound to the model host. The model host must also be allowed by egress policy. OpenCode has no documented base-URL env var in sbx docs; it reads project-level `opencode.json` from the workspace, so the provider `baseURL` has to go there. Unverified (docs only). | `[CLI]` `[SPEC]` | Claude: `sbx secret set-custom --sandbox NAME --host models.example.com --env ANTHROPIC_API_KEY --command 'cat /path/key'`; `sbx policy allow network --sandbox NAME models.example.com:443`; `sbx create claude . -e ANTHROPIC_BASE_URL=https://models.example.com --name NAME`. OpenCode: write `opencode.json` provider `options.baseURL` into the workspace, same secret/policy steps. |
| 5 | Agent versions; pinning | **Supported for Claude Code and OpenCode via kit refs; not via built-in names.** Built-in `claude`/`opencode` select sbx's bundled (v2) kit and cannot be pinned. v3 workload kits take a `version` arg. Published tags `[HUB]`: `docker/sbx-kit-claude`: 2.1.267, 2.1.273, 2.1.274, 2.1.278, 2.1.285, 2.1.288, 2.1.289, 2.1.291, 2.1.292, 2.1.296 (+ `latest`, 1.0.0). `docker/sbx-kit-opencode`: 1.18.31, 1.18.33 (+ `latest`). | `[HUB]` `[SPEC]` `[DOCS]` | `sbx run docker.io/docker/sbx-kit-claude:2.1.267 .` ; `sbx run docker.io/docker/sbx-kit-opencode:1.18.33 .` ; arg override: `--kit-arg version=2.1.292`. Needs sbx >= 0.45. |
| 6 | Context files (prompts, skills) available to the agent | **Supported.** Two routes. (a) Generated mixin kit: `agent-context@2` (inline text) for instructions and `agent-skill@1` for skill dirs bundled in the kit image. (b) Without building a kit: `sbx cp` into the sandbox after create. Targets: Claude `~/.claude/CLAUDE.md` and `~/.claude/skills/<name>/SKILL.md`; OpenCode `~/.config/opencode/AGENTS.md` and `~/.config/opencode/skills/<name>/`. Host `~/.claude` is NOT visible in the sandbox (project-level config in the workspace only). Unverified (docs only). | `[SPEC]` `[CLI]` `[DOCS]` | Kit: `capabilities: [{type: com.docker.sandbox/agent-context@2, config: {filename: CLAUDE.md, directory: /home/agent/.claude, content: "..."}}, {type: com.docker.sandbox/agent-skill@1, config: {path: /opt/capm/skills/foo}}]`. Cp: `sbx create claude . --name N && sbx cp ./ctx/CLAUDE.md N:/home/agent/.claude/ && sbx cp ./ctx/skills N:/home/agent/.claude/` (the skills dir is writable, store linked read-only). Project-level fallback: `CLAUDE.md` / `AGENTS.md` in the workspace. |
| 7 | Remote MCP servers and bearer tokens, per agent | **Supported, with a different network model.** `sbx mcp add NAME --url https://...` registers on the host; every sandbox runs an MCP gateway and the sbx claude and opencode kits register that gateway with the agent automatically. Bearer: header template with a secret placeholder, value stored as `mcp:NAME:KEY`. The agent talks only to the gateway, not to the MCP host. Unverified (docs only). | `[DOCS]` `[CLI]` `[SPEC]` | `sbx mcp add acme --url https://mcp.acme.com/mcp --skip-auth --header 'Authorization: Bearer ${api-key}'` ; `printf %s "$TOKEN" \| sbx secret set mcp:acme:api-key` ; `sbx create claude . --static-mcp acme --name N`. Check: `sbx mcp inspect acme`. Restart sandbox/sandboxd after changing the secret. |

## Manifest and `inspect` changes required (read before Task 1)

Nothing is "not supported", but four answers differ from the working assumptions, and everything runtime-related is unverified. Changes, in order of importance:

1. **MCP traffic does not originate in the sandbox.** The gateway runs on the host and the agent only connects to it. The design rule "an MCP URL's domain is automatically part of the enforced egress list" would therefore be wrong if read as "sandbox egress". Change `inspect` to show MCP URLs in their own line, "reached through the sbx MCP gateway on your machine (host-side, not sandbox egress)", plus the secret name. Do not add MCP hosts to the sandbox egress allowlist. **This touches the Global Constraint "there is no hidden network access / MCP URLs must appear in the egress list": it is still satisfied (nothing is hidden) but the wording of the constraint and the egress-list placement change. Per Task 0 Step 3 this needs a user decision before Task 1.**
2. **Exact-hostname enforcement depends on the baseline.** `inspect` must not claim "the sandbox can reach only these hosts" unless capm run enforces it. Options: (a) `capm run` generates a v3 mixin kit with `network-policy@2` and aborts if the effective policy (`sbx policy ls NAME`) contains anything wider than the manifest plus the base agent's own hosts; or (b) `capm run` requires `sbx policy init deny-all` as a precondition. The manifest keeps `network.egress: [exact-host]`. Remove wildcards (already out of scope for v1). Port is fixed to 443.
3. **Base agent hosts must be listed.** The built-in claude kit allows api.anthropic.com, platform.claude.com, downloads.claude.ai, claude.com, mcp-proxy.anthropic.com, bridge.claudeusercontent.com (all :443); opencode adds a broad multi-provider list. `inspect` should print "base agent (sbx) egress" separately from "bundle egress" and from "model endpoint (supplied by you)". capm should not let a bundle claim the base agent's hosts as its own.
4. **Mounts: manifest declares logical name + mode only.** Container path is sbx's choice and the host path comes from the installer at `run`. Schema: `mounts: [{name, mode: ro|rw, description}]`, no host path, no target path. Do not promise a fixed in-sandbox path.
5. **Secrets: manifest `secrets` entries need a binding type.** sbx only has fixed service names plus experimental `set-custom` (env var + host binding). Manifest secret = `{name, description, env: NAME}` and `capm run` binds it with `set-custom --sandbox`. MCP bearer secrets map to `mcp:<server>:<name>` instead. These are global-store names unless `--sandbox` scoped (set-custom supports it; MCP secrets are global, so namespace them as `capm-<bundle>-<name>` to avoid cross-bundle collision). Custom secrets are experimental: say so in the docs.
6. **Base agent pin = OCI kit ref.** Manifest `agent: {name: claude|opencode, version: x.y.z}`. `capm run` maps to `docker.io/docker/sbx-kit-<name>:<version>`; reject versions not in the published tag list (claude 2.1.267-2.1.296 subset above; opencode 1.18.31, 1.18.33). Mapping is open question #3 from the spec ("how a version pin maps to sbx's agent images"): answered. Requires sbx >= 0.45 and network access to docker.io at first run.
7. **Model endpoint for OpenCode is a file, not an env var.** For OpenCode, `capm run` has to write an `opencode.json` provider block; for Claude, `ANTHROPIC_BASE_URL` via `-e`. Keep "model endpoint supplied by you" as a separate `inspect` line and add its host to the per-sandbox allow rule at run time only.
8. **Context files can carry config the sandbox honours.** Because context is delivered via kit `agent-context`/skills, `inspect` must keep the prompt-injection caveat already in the design, and list the destination paths above.

## Verification limit

**Verification limit, read this first.** `sbx` requires `sbx login` (a Docker account) before the daemon will start or any sandbox can be created (`sbx ls`, `sbx policy ls`, `sbx kit inspect` all return `error: not signed in to Docker`). I did not sign in. So **no sandbox was created and no answer below was proven by running a sandbox.** What was verified:

- `[CLI]` flag and subcommand existence and semantics, read from `sbx ... --help` on the installed binary.
- `[SPEC]` the Docker Sandbox Kit v3 spec and the shipped claude/opencode kit sources (github.com/docker/sandbox-kit-spec).
- `[HUB]` published kit tags, queried live from Docker Hub.
- `[DOCS]` pages under https://docs.docker.com/ai/sandboxes/.

Anything not run in a real sandbox is marked "unverified (docs only)" in the table. Re-run the "To verify" step once someone with a Docker login can do it (about 15 minutes, commands below). No sandboxes or other resources were created, so there is nothing to clean up.

## To verify (needs `sbx login`; do before freezing the schema)

```sh
sbx login && sbx daemon start
sbx policy ls                                   # what is allowed by default
mkdir -p /tmp/ro /tmp/rw && echo x > /tmp/ro/f
sbx create shell /tmp/rw /tmp/ro:ro --name spike   # Q2
sbx exec spike sh -c 'touch /tmp/ro/f2'            # expect failure (path may differ: check `sbx ls`/inspect)
sbx exec spike sh -c 'curl -sS -m5 https://example.com' # Q1 baseline
sbx policy allow network --sandbox spike example.com:443   # Q1 per-sandbox rule
sbx secret set-custom --sandbox spike --host example.com --env DUMMY_KEY --value dummy123   # Q3
sbx exec spike sh -c 'echo $DUMMY_KEY'          # expect a placeholder, not dummy123
sbx kit inspect docker.io/docker/sbx-kit-claude:2.1.267   # Q5
sbx cp ./ctx spike:/home/agent/ctx              # Q6
sbx mcp add t --url https://example.com/mcp --skip-auth --header 'Authorization: Bearer ${k}'  # Q7
sbx rm spike; sbx mcp rm t; sbx secret rm ...; sbx policy rm ...   # cleanup
```

## Sources

- https://docs.docker.com/ai/sandboxes/ (security, mcp-gateway, agents/claude-code, agents/opencode, customize)
- https://github.com/docker/sandbox-kit-spec : `docs/spec/SPEC-v3.md`, capabilities `network-policy@2`, `credential@1`, `host-mount@1`, `agent-context@2`, `agent-skills@1`, `agent-skill@1`, `docs/agent-context-placement.md`, `examples/claude/claude.yaml`, `examples/opencode/opencode.yaml`
- Docker Hub tags: hub.docker.com/r/docker/sbx-kit-claude, hub.docker.com/r/docker/sbx-kit-opencode
