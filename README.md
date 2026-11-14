# capm

**Share AI agents the way you share packages. Run them in a sandbox that enforces exactly what they declare.**

> **Status: v1 registry is live** at <https://capm.masondrake.dev>. See [docs/getting-started.md](docs/getting-started.md) to publish and pull bundles, and [docs/security-notes.md](docs/security-notes.md) for what v1 does and does not protect you from. Parts of this README still describe the intended design rather than what v1 does. Expect breaking changes.

Install the CLI: `curl -fsSL https://capm.masondrake.dev/install.sh | sh`

## The problem

People are building personal agents to help with their work, and coworkers often hit the same problems those agents solve. But there's no good way to hand an agent to someone else. Configs live in dotfiles, secrets live in `.env` files, the agent assumes a specific model provider, and the person receiving it has no idea what it can touch on their machine.

Existing tools mostly distribute agent *configuration* (prompts, skills, MCP wiring). They don't make an agent's behavior verifiable, and they don't contain it.

## The idea

Every agent published to capm ships with a **manifest** that declares what it needs and what it's allowed to do. When you install and run an agent, capm translates that manifest into sandbox policy, so the runtime enforces the declaration instead of trusting it.

Think of it as Android-style permissions for agents:

- **Declared:** "this agent reaches `api.github.com`, reads `./workspace`, and needs `GITHUB_TOKEN`."
- **Enforced:** the agent runs in an isolated microVM where everything else is blocked.
- **Inspectable:** before you install, you see a plain summary of those permissions.

- Goal, role, inputs, deliverables, safeguards

## Design principles

1. **Local first.** Agents are downloaded and run on the installer's machine. Hosted runtimes (e.g. Kata Containers on Kubernetes) may come later, driven by the same manifest.
2. **The installer pays.** The person running the agent brings their own API key or points it at a free/local model. Agents talk to an OpenAI-compatible endpoint injected at run time, so no agent is locked to one provider.
3. **No secrets in packages.** Manifests list secret *names* only. Values are injected at run time from the sandbox secret store.
4. **Runtime agnostic spec.** The manifest never contains runtime-specific fields. Each runtime (sbx today, others later) is a translator from the same spec.
5. **Enforced vs. described.** capm keeps a hard line between what the runtime guarantees and what the author claims (see [Summaries](#summaries)).

## How it works

```
 author                         registry                     installer
 ──────                         ────────                     ─────────
 agent image + manifest  ──▶  OCI artifact (signed)  ──▶  inspect permissions
                                                           │
                                                           ▼
                                                     manifest → sandbox policy
                                                     secrets injected at run time
                                                     model endpoint injected
                                                           │
                                                           ▼
                                                     agent runs in microVM
```

- **Packaging:** agents are stored as OCI artifacts, so any OCI registry (Docker Hub, GHCR, a self-hosted registry) works. Versioning comes from tags and digests.
- **Signing:** packages are signed (cosign) so installers can verify who published them.
- **Runtime (v0):** [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`). Each agent gets its own microVM with its own kernel, filesystem, and Docker daemon. The manifest's egress list becomes sbx network policy, and required secrets are pulled from the sbx secret store.

## Manifest

A bundle is a directory with a `capm.yaml`, the context files it lists, and optionally a root `README.md`. It builds on a base agent kit (Claude Code or OpenCode) rather than shipping its own image. `capm init` writes a commented starter file.

```yaml
apiVersion: capm/v0
kind: Agent
metadata:
  name: pr-reviewer
  version: 0.1.0
  description: Reviews open pull requests and leaves comments.
  authors: [MasonD-007]

base:
  agent: claude-code       # or opencode
  version: 2.1.292         # kit tag

interface:
  type: tty                # the only supported type

model:
  api: openai-compatible   # base URL and key are supplied by whoever runs it
  requires:
    toolCalling: true
    minContextTokens: 32000

permissions:
  egress: [api.github.com]
  mounts:
    - path: ./workspace
      mode: read-only

secrets:
  - name: GITHUB_TOKEN
    description: Token used to read pull requests

mcp:
  - name: gh
    url: https://mcp.example.com/mcp
    secret: GITHUB_TOKEN   # sent only to this server

context:
  - prompts/review.md
```

| Field | Purpose |
|---|---|
| `metadata` | Name, version, description, authors, and an optional `repository` link |
| `base` | The agent kit the bundle runs on, and its version |
| `interface.type` | How the person running it talks to the agent |
| `model` | What the agent needs from a model; the endpoint itself is supplied at run time |
| `permissions.egress` | Hosts the agent declares it reaches (exact hostnames, no wildcards) |
| `permissions.mounts` | Workspace paths exposed to the sandbox, and in what mode |
| `secrets` | Names of secrets supplied at run time; never values |
| `mcp` | Remote MCP servers, each optionally bound to one secret |
| `context` | Files published with the bundle and given to the agent |

These are **declared** permissions. `capm run` does not yet restrict the sandbox to exactly the listed hosts; see [docs/security-notes.md](docs/security-notes.md).

## CLI

```
capm init      Scaffold a new bundle
capm lint      Check a bundle before publishing
capm inspect   Show a bundle's declared permissions and risk labels
capm login     Sign in with GitHub
capm push      Publish a bundle
capm search    Find bundles (also: capm list)
capm pull      Download a bundle; check its sha256 digest and, when it is signed, its signature
capm run       Launch a bundle in a Docker Sandbox
```

`capm` with no arguments lists every command. [docs/getting-started.md](docs/getting-started.md) walks through writing and publishing a first bundle.

## Summaries

capm shows two kinds of summary and never mixes them:

- **Enforced summary:** generated deterministically from the manifest. Network access, mounts, and required secrets. This is a guarantee because the runtime enforces it.
- **Described summary:** an LLM-generated description of what the agent does, based on its code and prompts. Useful, but it reflects what the author built and claims, and can be gamed. It is always labeled as unverified.

## Security model and known limits

- **The sandbox protects your host, not your keys from the agent.** Any secret you inject is readable by the agent's code. The egress allowlist is what stops a key from leaving: if an agent can only reach `api.anthropic.com`, it has nowhere to send your token. Review egress lists carefully.
- **Signing proves authorship, not good intent.** A signed package tells you who published it, not that it's safe.
- **Isolation strength depends on the runtime.** v0 relies on sbx microVM isolation and its network policy enforcement.

## Roadmap

- [ ] Finalize v0 manifest spec, validated against two very different agents (a coding agent config bundle and a custom Go agent)
- [ ] `capm inspect`: manifest parsing and enforced summary
- [ ] `capm push` / `capm pull` with OCI artifacts and signature verification
- [ ] `capm run` on sbx: egress policy, secret injection, model endpoint injection
- [ ] Additional interfaces (HTTP, MCP, A2A)
- [ ] Kubernetes runtime via Kata Containers
- [ ] Web UI for browsing agents and their permission summaries

## Contributing

The project is at the spec stage, so the most useful contributions right now are feedback on the manifest: agents you'd want to share that don't fit it. Open an issue.

## License

TBD
