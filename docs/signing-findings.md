# Bundle signing spike: findings

Spike date 2026-11-13, branch `spike/signing`. Throwaway code and raw outputs
live in `spike/signing/` (its own Go module, built with `GOWORK=off`; nothing
under `cli/`, `backend/`, `manifest/` was touched). This is a decision document
for the review that the plan (B2) requires before any implementation.

Labels used below: **RAN** = executed on this machine, output in
`spike/signing/results/`. **READ** = from reading library source in the module
cache or public documentation, not executed. **UNVERIFIED** = from memory or
inference, not checked against a source.

## 1. Recommendation

1. **Proceed, narrowly: CI-only keyless signing, offline verification in the CLI with `sigstore-go`.** Verification works fully offline against an embedded trusted root, in about 3 ms of work (11-13 ms per process), and the identity policy can be anchored on the numeric GitHub owner id (RAN).
2. **The price is size and dependencies, and the owner must accept it explicitly:** the CLI goes from about 8 MB to an estimated 21-24 MB, and `cli/go.mod` from 3 requirements and an 8-line `go.sum` to about 66 requirements and about 350 `go.sum` lines (68 modules linked). No CGO. If that is unacceptable the answer is "not yet", because the cheaper alternatives (shelling out to `cosign`, GitHub's attestation API) do not remove the need for the CLI to verify.
3. **Do not sign from laptops.** Interactive Sigstore login yields a certificate bound to an email address, never to a GitHub numeric id, so it cannot satisfy the owner-id policy. Laptop pushes stay labelled `unsigned`.
4. **Do not build a TUF client into the CLI.** Embed `trusted_root.json` (6.8 KB), refresh it by releasing, and print a self-update hint when verification fails on an unknown key.
5. **First pull request:** a verifier package plus embedded root plus fixture tests, with no command, backend or UI change (section 6).

## 2. What was run and observed

Environment: macOS arm64 (Darwin 27.2.0), Go 1.27.4, `GOWORK=off`, network access
to the Go module proxy, `proxy.golang.org`, `api.github.com`, GitHub release
downloads, `raw.githubusercontent.com` and the public Sigstore TUF CDN worked
throughout. Nothing was signed, no browser was opened, no credentials were used,
`capm.masondrake.dev` was not contacted.

### A. Library survey

| Option | Covers | Version examined | Licence | Offline verify from bundle + root | Notes |
|---|---|---|---|---|---|
| `github.com/sigstore/sigstore-go` | verify and sign | v1.4.0 (2026-10-29); 25 tagged versions since v0.1.0 (2024-01) | Apache-2.0 | **Yes, RAN** (`root.NewTrustedRootFromJSON` + `verify.NewVerifier`) | v1.0.0 2025-05-12, v1.1.0 2025-07-14, v1.2.0 2026-06-03, v1.3.0 2026-07-30, v1.4.0 2026-10-29. Irregular: 11 months between v1.1 and v1.2, then three minors in five months. Semver 1.x. The Sigstore client libraries' own recommended path. |
| `github.com/sigstore/cosign/v3` as a library | both, CLI-oriented API | v3.1.4 (2026-10-20); v3.0.0 was 2025-10-07 | Apache-2.0 | Possible, but API is cosign-internal | RAN: a main importing only `pkg/cosign` gives a **504-module** graph and a 20.4 MB stripped binary. It wraps sigstore-go anyway. Rejected. `cosign/v2` is at v2.6.5 (2026-08-05), maintenance line. |
| Shell out to a `cosign` binary | both | releases v3.1.4: binaries are 99-146 MB | Apache-2.0 | `cosign verify-blob --bundle` supports offline verification (READ) | Requires every user to install a 100 MB tool. Disqualified for a tool that must verify on `pull`/`run`. Fine as a *publisher-side* option in CI. |
| GitHub artifact attestations (`gh attestation`, `actions/attest*`) | sign (in Actions) and verify | `gh` v2.104.0 | MIT (`cli/cli`) | `gh attestation verify --bundle` can verify offline with a trusted root (READ/UNVERIFIED) | Same underlying technology, see section 3 (alternative). Not a library the capm CLI can embed cheaply. |
| `github.com/theupdateframework/go-tuf/v2` | TUF client used by sigstore-go | v2.4.2 | Apache-2.0 | n/a | Linked into the verifier even if unused (see below). |

All 68 modules linked into the verifier classify as Apache-2.0 (48), BSD (12),
MIT (7), by a keyword heuristic (`results/C-licenses.txt`); none unknown or
copyleft. Redistributing binaries means shipping a third-party notices file; the
release process has none today (UNVERIFIED for the repo as a whole: not checked).

### B. Verification prototype

Code: `spike/signing/verify/verify.go` (the verifier, about 110 lines),
`spike/signing/cmd/spikeverify` (demo CLI), driver `spike/signing/run-experiments.sh`,
full output `results/B-verification-cases.txt`. Every verification ran under
`sandbox-exec` with `(deny network*)`, so the offline claim is enforced, not assumed.

Verifier configuration: `WithTransparencyLog(1)` (Rekor inclusion proof or
promise checked against the trusted root's log keys), `WithIntegratedTimestamps(1)`
(the log's integrated time is the clock for the 10-minute Fulcio certificate),
`WithSignedCertificateTimestamps(1)` (CT SCT), plus `WithArtifactDigest` and
`WithCertificateIdentity`.

Two real, public bundles were used:

1. **Case 1, `messageSignature` bundle**, the same shape capm would produce:
   `cosign-darwin-arm64` from the sigstore/cosign v3.1.4 release with its
   `.sigstore.json` (sha256 `9f9b8cd5...`). Bundle v0.3, Rekor v1 entry with inclusion
   proof and SET. Its identity is **not** GitHub Actions: SAN
   `keyless@projectsigstore.iam.gserviceaccount.com`, issuer `https://accounts.google.com`.
2. **Case 2, GitHub Actions identity**: the sigstore-go test fixture
   `sigstore.js@2.0.0-provenance.sigstore.json` (signed 2023-08-18 by a sigstore-js
   workflow). It is a DSSE/in-toto bundle (sha512 subject), not a `messageSignature`,
   but the certificate and the policy path are identical. I found no public
   `messageSignature` bundle with an Actions certificate to download cheaply, so the
   Actions policy was not exercised on the exact shape capm would emit (see risks).

| # | Scenario | Result |
|---|---|---|
| 1.1 | valid digest + GCP identity policy | OK |
| 1.2 | wrong digest | `artifact does not match digest` |
| 1.3 | wrong SAN | `no matching CertificateIdentity` |
| 1.4 | wrong issuer | `no matching CertificateIdentity` |
| 1.5 | Actions policy (`owner=sigstore`) against a non-Actions cert | rejected |
| 1.6 | tampered signature / certificate / inclusion-proof hash / SET; tlog entry stripped | all rejected (5 cases) |
| 2.1 | valid, issuer + `owner=sigstore` + owner id `71096353` | OK, prints repo URI and owner id from the cert |
| 2.3 | wrong digest | rejected |
| 2.4 | wrong owner login (`evil`) | rejected |
| 2.5 | login prefix `sig` vs `sigstore` | rejected (regexp is anchored and the login is `QuoteMeta`d) |
| 2.6 | right login, **wrong numeric owner id** (`71096354`) | rejected: `expected SourceRepositoryOwnerIdentifier to be "71096354", got "71096353"` |
| 2.7 | wrong issuer | rejected |
| 2.8 | tampered signature / cert / proof / SET / stripped tlog | all rejected (5 cases) |

Totals: 3 successes, 19 expected failures, 0 surprises. Caveat on tamper tests:
all ten tampered bundles fail at the *transparency-log* check (the log entry
commits to the signature and certificate), not at the raw signature check, so
these tests prove a tampered bundle is rejected, not which layer catches it. The
signature check itself is exercised by the digest cases. An in-memory test with
sigstore-go's own fake CA (`pkg/testing/ca.VirtualSigstore`) also passes
(`go test ./verify`): sign, verify, and reject wrong digest, SAN, issuer and a
certificate from an untrusted CA.

**Trusted root and TUF.**
- Default behaviour (READ, `pkg/tuf/options.go`, and RAN): `tuf.DefaultOptions()` uses
  mirror `https://tuf-repo-cdn.sigstore.dev`, cache `$HOME/.sigstore/tuf`,
  `CacheValidity` 0 (meaning it refreshes on every client creation, a network call per
  run). A cold fetch of `trusted_root.json` took 0.8-1.0 s here
  (`results/B-tuf-cache.txt`). I used a temp cache dir, not `~/.sigstore`.
- Embedded TUF anchor: sigstore-go ships `root.json` v14 which **expired 2026-06-22**;
  the client keeps working only because it walks the root chain over the network. The
  live repository is at root v16 (expires 2027-04-22). The timestamp role expires about
  a week out (2026-11-19) and is re-signed continually. Conclusion: the TUF machinery
  is online by design; an offline CLI should not use it.
- Pinning for offline use: `root.NewTrustedRootFromJSON(bytes)` takes a plain
  `trusted_root.json` (6,787 bytes today, one file, `//go:embed`-able). It has no
  expiry of its own. `tuf.Options` also offers `ForceCache`/`DisableLocalCache`, not needed.
- Contents today: 2 Rekor logs (`rekor.sigstore.dev` from 2021, `log2025-1.rekor.sigstore.dev`
  from 2025-09-23), 2 Fulcio CAs (the first ended 2022-12-31, the second open-ended),
  2 CT logs, 1 TSA (from 2025-07-04). Rotation rate: root v14 to v16 in under a year;
  trusted-root content changes roughly once or twice a year (inferred from the validity
  windows above, UNVERIFIED as a general rate).
- Stale root experiment (RAN, `results/B-stale-root.txt`): two older roots from the
  sigstore-go v1.4.0 tree (without `log2025-1`) **still verified** the Oct 2026 cosign
  bundle, because that bundle is in Rekor v1 and the CA and log keys are unchanged.
  So a stale embedded root breaks only bundles that use a key or log the old root has
  never heard of (a new Rekor shard, Fulcio intermediate, or CT log). Those would
  fail closed with an opaque error. Current `signing_config.v0.2.json` (fetched through
  TUF) still selects Rekor v1 only, so new signatures are not yet on `log2025-1`.
  Whether a given future rotation breaks old CLIs is UNVERIFIED (I could not make a
  bundle that uses a key absent from a root).

### C. Cost measurement

Method (`run-sizes.sh`, `run-deps.sh`): `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"`
for all four release targets, identical to `scripts/build-cli.sh` except the
`-X main.version` value on the spike mains. Three binaries per target: the real
`cli/` (built in place with the workspace, unmodified), `emptymain` (stdlib-only: read
file, sha256, print), `verifymain` (same plus `verify.Verify` and an embedded
`trusted_root.json`). I cannot link the verifier into the real CLI without editing it,
so the added size is estimated as `verifymain - baseline`. Error bars: the baseline
choice matters. Against the trivial `emptymain` the delta overstates (the real CLI
already links `net/http`, `crypto/tls`, `encoding/json`, `regexp`, etc.); against
`stdbase` (which imports those same stdlib packages) it is closer. I estimate the true
increment as the `stdbase` delta, plus or minus 1-2 MB.

| Target | real capm CLI (bytes) | empty main | + verifier | delta vs empty | delta vs stdlib-matched baseline |
|---|---:|---:|---:|---:|---:|
| darwin/arm64 (host) | 7,835,282 | 1,791,490 | 17,981,426 | +16,189,936 (+207%) | +13,474,768 (+172%) |
| linux/amd64 | 8,368,288 | 1,835,168 | 18,550,944 | +16,715,776 (+200%) | +13,824,000 (+165%) |
| darwin/amd64 | 8,528,560 | 1,871,744 | 19,108,080 | | |
| linux/arm64 | 7,667,872 | 1,835,168 | 17,432,736 | | |

Estimated real CLI with verification: about 21 MB (darwin/arm64) to 22 MB (linux/amd64),
at most about 24 MB. That is roughly 2.7x today. (For scale, the `gh` release binaries
are also tens of MB; this is a cost, not a showstopper.)

All four targets build with `CGO_ENABLED=0` (RAN; `go list` reports no cgo files in any
non-stdlib dependency).

Dependencies (RAN, `results/C-deps.txt`, `C-minimal-module.txt`):

| | now (`cli`) | with verifier |
|---|---:|---:|
| `go list -m all` | 6 | 377 (graph, mostly pruned unused) |
| `go.mod` requirements | 3 direct + 1 indirect | 1 direct + about 65 indirect |
| modules actually linked (`go list -deps`) | 5 | 68 |
| non-stdlib packages linked | 7 | 329 |
| `go.sum` lines | 8 | 350 |

Notable heavyweight linked modules: `google.golang.org/grpc` (65 packages),
`protobuf` (38), `sigstore/rekor` (20), `go.opentelemetry.io/otel` (13),
`certificate-transparency-go` (12), `go-openapi/*`, `go-tuf/v2`, `k8s.io/klog`.
They arrive because `sigstore-go/pkg/root` imports the TUF client and the Rekor
generated clients, not because verification needs a network. A hand-written verifier
for only `messageSignature` + `hashedrekord` v1 could be a few hundred lines on the
stdlib, but it would reimplement certificate-chain, SCT, checkpoint and Merkle-proof
verification for a security product. Not recommended.

Time (RAN, `results/C-timing.txt`; 21 fresh processes, first dropped, embedded
root, digest passed as hex so hashing is excluded, bundle in page cache):

| Bundle | median | min | max |
|---|---:|---:|---:|
| messageSignature, Rekor v1 proof + SET + SCT | 11.9 ms | 11.2 | 14.0 |
| DSSE, GitHub Actions cert | 12.8 ms | 11.5 | 19.7 |
| process start only (`-h`) | 9.6 ms | | |

So verification itself is about 2-3 ms; the first process after a fresh build measured
about 66 ms internally (cold disk), still negligible next to a bundle download. The
tarball's sha256 is already computed by `cli/cmd_pull.go` and can be reused.

### D. Signing feasibility (READ only; nothing was signed)

What `sigstore-go` v1.4.0 provides (`pkg/sign`, `docs/signing.md`, `examples/sigstore-go-signing`):
it does **not** fetch OIDC tokens. `sign.CertificateProviderOptions.IDToken` takes a JWT
the caller obtained. The calls for signing the tarball bytes:

```go
kp, _ := sign.NewEphemeralKeypair(nil)                         // P-256, in memory
cfg, _ := root.FetchSigningConfig()                            // via TUF: Fulcio/Rekor/TSA URLs
fulcio := sign.NewFulcio(&sign.FulcioOptions{BaseURL: "https://fulcio.sigstore.dev", Timeout: 30*time.Second, Retries: 1})
rekor  := sign.NewRekor(&sign.RekorOptions{BaseURL: "https://rekor.sigstore.dev", Version: 1, Retries: 1})
b, err := sign.Bundle(&sign.PlainData{Data: tarball}, kp, sign.BundleOptions{
    CertificateProvider:        fulcio,
    CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: jwt},
    TransparencyLogs:           []sign.Transparency{rekor},
    TrustedRoot:                tr, // optional: library verifies its own output
})
json, _ := protojson.Marshal(b)                                // the .sigstore.json to upload
```

- `sign.PlainData` signs the raw bytes, producing a `messageSignature` bundle whose
  digest is sha256(tarball): exactly what `capm push` and `pull` already compute, and
  interoperable with `cosign verify-blob --bundle`. The library's own example comments
  warn that the signing config may name a newer Rekor API version than older verifying
  clients support: select versions explicitly (`root.SelectService`).
- **(a) GitHub Actions**: the job needs `permissions: id-token: write`; the ambient token
  is `GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore` with
  `Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN`, JSON field `value` (GitHub
  documentation, UNVERIFIED here; sigstore-go has no helper for it, about 25 lines of
  `net/http`). Audience must be `sigstore` (Fulcio documentation).
- **(b) Interactive laptop**: `github.com/sigstore/sigstore/pkg/oauthflow` (v1.11.1,
  already in the graph): `oauthflow.OIDConnect("https://oauth2.sigstore.dev/auth",
  "sigstore", "", "", oauthflow.PublicInstanceGithubIDTokenGetter)` opens a browser
  (loopback redirect, PKCE) or `NewDeviceFlowTokenGetterForIssuer` for a device flow;
  `connector_id=https://github.com/login/oauth` selects GitHub in Dex. The returned
  `RawString` goes into `IDToken`. Not run.
- Uploaded: Fulcio receives the ID token and the ephemeral public key plus a proof of
  possession; it returns a 10-minute certificate (observed validity: exactly 10 minutes
  in both real bundles). Rekor receives a `hashedrekord` entry: artifact sha256,
  signature, and the **full certificate**. All of it is public and permanent.
- **Public in Rekor for an Actions signature** (read from the real fixture, RAN
  `results/D-cert-shapes.txt`): issuer; SAN = `https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>`;
  repository URI and numeric id; repository owner URI and numeric id; workflow ref, the
  commit SHA, the trigger event, runner environment, and the Actions **run URL**
  (`runInvocationURI`). The fixture also carries `sourceRepositoryVisibilityAtSigning`.
  Nothing says the repository must be public: **signing from a private repository
  publishes its owner, name, workflow path, commit SHA and run URL** (inference from
  the fields; UNVERIFIED that Fulcio does not refuse private repos).
- **Email for interactive GitHub logins: yes** (Fulcio documentation, READ): "GitHub
  (Note that this is the email of the user, not the GitHub username)"; the email is
  the certificate SAN and therefore permanently public. The issuer extension would be
  `https://github.com/login/oauth` (constant in oauthflow; the federated-issuer
  behaviour is documented but UNVERIFIED by observation).
- **Rate limits and policy**: I found none published in the Sigstore docs repository or
  the Fulcio/Rekor documentation (READ). Rekor's public instance states a 99.5% SLO and an
  on-call team; the staging instance has no SLO and must not be used for production.
  Per-IP/per-identity limits are UNVERIFIED; the library retries on HTTP 429/5xx
  (`Retries`). Plan on signing taking seconds and failing sometimes: CI needs retry and a
  non-fatal path.
- **Local fake infrastructure for tests**: `sigstore-go/pkg/testing/ca.VirtualSigstore`
  (public, in-memory Fulcio + Rekor + CT + TSA, usable as `root.TrustedMaterial`). Used in
  `verify_test.go` (RAN). Limitation: it issues email-SAN certificates with only the
  legacy issuer OID (`1.3.6.1.4.1.57264.1.1`), not the Actions OIDs, so the owner-id
  policy cannot be tested with it; use real fixture bundles or build a test CA with
  `crypto/x509` and the extra extensions.

Certificate shapes to write the policy against (RAN, `results/D-cert-shapes.txt`):

| | issuer (OID .8) | SAN | other fields |
|---|---|---|---|
| (i) Actions workflow | `https://token.actions.githubusercontent.com` | URI `https://github.com/<repo-of-workflow-file>/.github/workflows/<file>@<ref>` (`job_workflow_ref`) | `.12` source repo URI `https://github.com/<owner>/<repo>`, `.15` repo id, `.16` owner URI `https://github.com/<owner>`, **`.17` owner numeric id** (`71096353` in the fixture), `.9` build signer URI, `.13` commit, `.14` ref |
| (ii) interactive GitHub | `https://github.com/login/oauth` (READ) | email address | no owner id, no login |

## 3. Policy design (section E)

**E1. Required certificate identity.** For bundle `owner/name`, require all of:
1. issuer exactly `https://token.actions.githubusercontent.com`;
2. Fulcio extension `.16` (Source Repository Owner URI) equals `https://github.com/<owner>`;
3. extension `.17` (Source Repository Owner Identifier) equals the owner's numeric id (below);
4. digest equals the SHA-256 of the downloaded tarball (the CLI's own computation, not the registry's reported digest);
5. valid Rekor inclusion in the embedded root, with the SCT.

The numeric ids available are the ones in the table: repository id (`.15`) and owner id
(`.17`), both from GitHub's `repository_id` / `repository_owner_id` token claims
(Fulcio `oid-info.md`, READ; present in the 2023 fixture, RAN). **Do not rely on the SAN
alone**: the SAN is `job_workflow_ref`, the repository holding the *workflow file*. With
a reusable workflow (capm's planned D2 Action) the SAN points at the Action's repository, not the
publisher's, while `.17` still names the repository that triggered the run. Treat the SAN as
display and optional hardening (for example an allow-list), not as the owner proof. The
library supports extension matching (`certificate.Extensions{SourceRepositoryOwnerIdentifier: ...}`,
RAN case 2.6) but only by exact equality, so the login check uses `.16` exact compare.

*What it proves*: a workflow run in some repository owned by that GitHub account (user
or organisation, any repo, including any member-writable repo of an org) signed this
digest. It does not prove a particular repo or reviewed code. Optional tightening
(recommended): also pin the repository id (`.15`) on first sight, as part of the same
signing-identity pin the plan describes under A5, and treat a change as an escalation.

**Where the expected numeric id comes from.** Not from the registry. On first use
the CLI verifies the bundle with issuer + `.16 == https://github.com/<owner>` and then
*reads `.17` from the verified certificate*: GitHub asserted the login-to-id binding at
signing time and Sigstore logged it, so the id is attested rather than registry-reported.
The CLI then: refuses if it disagrees with a `known.json` pin; refuses if the registry's
reported `ownerId` disagrees; otherwise pins it in `known.json` (`ownerId` already exists
there). After the pin, a login takeover (same login, new id) fails the policy even on
signed bundles. Limits stay as the current notes document: pins protect only people who
pulled before, and an attacker who legitimately owns the re-registered login can sign
bundles that pass on someone's *first* use (the transparency log makes this detectable
by third parties, which `known.json` pinning alone does not). A registry that serves no
bundle is handled by the downgrade rule in E6. One check to confirm in implementation:
the registry's `ownerId` and GitHub's `repository_owner_id` are the same id space for
user-owned repos (both are GitHub account ids; UNVERIFIED against the live registry,
which I did not contact).

The signature does not bind `owner/name@version`, only the bytes. Replaying an old
signed tarball under a new version label is therefore possible unless the CLI also
checks that the manifest inside the verified tarball (`manifest.Name`, `manifest.Version`)
matches the name and version it asked for. Whether `pull` already does this was not
checked; it must, as part of this feature.

**E2. Laptop signing.** The certificate carries the GitHub account's email, not its login
or numeric id (READ). The CLI cannot map an email to the registry's numeric owner id
without GitHub API calls, and an email is not a stable identity (changeable, may be
unverified or private). **Recommendation: CI-only signing for v1. Interactive publishes
stay labelled `unsigned`.** If laptop signing is ever wanted, label it as a different
thing (`signed by dev@example.com, not linked to a GitHub account`), pin
(issuer, email) in `known.json`, and never count it as verified for owner-id purposes.
Requiring a browser login for every publish is also poor UX; publishers who want signed
bundles should publish from a workflow.

**E3. Storing the bundle.** Store it in the registry next to the tarball as the plan
says. The registry needs no trust because the bundle is self-authenticating: the
signature covers the digest, the certificate chains to the embedded Fulcio root, and
inclusion is checked against the embedded Rekor key. The registry can do exactly three
things: withhold the bundle (a downgrade, handled by E6), serve a wrong one (verification
fails closed), or replay an old valid one (caught by the digest and manifest checks).
Observed bundle sizes: 3.7-6.7 KB for the real bundles here; the plan's 64 KiB cap is
generous.

**E4. Offline verification and trusted-root lifecycle.** Embed `trusted_root.json` with
`//go:embed`; no TUF client, no cache directory, no network at verify time. Refresh by
releasing: a CI step fetches the root through the real TUF client (the `fetchroot` tool
here does this in about a second) and a scheduled workflow opens a PR when it differs, so
each release carries a root at most weeks old. Users who rarely update are exposed to
rotations only for *newly created* signatures; old bundles keep verifying (B, stale-root
experiment). On a verification failure caused by an unknown log or CA key, print "this
capm's embedded Sigstore trust root may be out of date; run `capm self-update`"; the
daily update notice already exists. Possible later addition, not now: an opt-in
`--trusted-root FILE` override. Because the fail-closed rule applies, a stale CLI that
meets bundles signed after a rotation will refuse them until updated; that cost is real
and is the main reason to keep `CAPM_REQUIRE_SIGNED` off by default for a long time.

**E5. Privacy: what to tell publishers.** Before the first signed publish, the CLI/Action
should state: signing writes a permanent, public, undeletable record to the Sigstore
public transparency log containing the bundle's SHA-256, and your signing certificate, which
includes: the GitHub repository URL and id, the owner id, the workflow file path and branch or
tag, the commit SHA, the trigger, and the Actions run URL; this applies to private
repositories too. Laptop signing would also publish your email address. The tarball
itself is not uploaded. There is no way to remove entries. Make signing opt-in at first
(`push --sign`), default off outside the Action.

**E6. Rollout.**
1. Optional. `inspect`, `list`, run confirmation and the website show a neutral
   `signed: owner/repo` or `unsigned`; no alarm colour for unsigned while nothing is signed.
2. A bundle that **has** a signature that fails verification is a hard error (fail closed,
   per the plan's Global Constraints), with a loudly named override flag.
3. Downgrade rule via `known.json`: once a version of `owner/name` (or any bundle of that
   owner) was seen signed with a pinned identity, a later unsigned version is refused
   unless `--allow-unsigned`; a different signing identity is an escalation. This is what
   keeps a hostile registry from stripping signatures.
4. `CAPM_REQUIRE_SIGNED=1` later. It would break: every existing bundle (none are
   signed), all laptop publishes, publishers using non-GitHub CI, and users with a stale
   embedded root (E4).

**E7. Alternative: GitHub artifact attestations.** Same technology: a Sigstore bundle, a
Fulcio certificate with the same OID extensions, usually an in-toto statement in DSSE.
Verifying it still needs a Sigstore verifier and a trusted root, so it does not shrink the
CLI. Observations (RAN): the unauthenticated REST endpoint
`GET /repos/cli/cli/attestations/sha256:<digest>` returned 200 and a `bundle_url` to a
snappy-compressed bundle (I decoded one with a 50-line decoder). That bundle, a GitHub
*release* attestation, was signed by **GitHub's own Fulcio** (`CN=Fulcio Intermediate l1,
O=GitHub, Inc.`, SAN `https://dotcom.releases.github.com`), with no Rekor entry, so verifying it
needs a second trusted root. GitHub's documentation says private repositories also use
GitHub's instance rather than the public-good one (UNVERIFIED here). Viable only if the
bundle is stored by the registry (so no GitHub API or token at pull time) and the
publisher uses public-good attestation from a public repository. Verdict: do not depend
on the GitHub API; attestations are a possible *publisher-side* convenience for D2 (the
Action could call `actions/attest` and upload the resulting bundle) as long as the CLI
accepts any valid public-good Sigstore bundle that meets the policy. Laptop publishes
still unsupported, consistent with E2.

**E8. Cheapest credible first step, and what not to build yet.** First step: PR 1 below.
Do not build yet: laptop/interactive signing, an in-CLI TUF client or auto-refresh,
`CAPM_REQUIRE_SIGNED` as default, a custom Fulcio/Rekor instance option, GitHub
attestation API fetching, SLSA/in-toto provenance predicates, Rekor monitoring for
login-takeover detection, revocation, the website label before the CLI can verify.

## 4. Costs

| Item | Measured / estimated |
|---|---|
| Binary size (real CLI → with verifier) | 7.8 MB → about 21 MB (darwin/arm64); 8.4 MB → about 22 MB (linux/amd64); +165-172% (stdlib-matched), +200-207% (naive); error ±1-2 MB; estimate, not a build of the real CLI |
| Direct dependencies | 3 → 4 (`sigstore-go`) |
| Modules linked | 5 → 68; `go.mod` requirements about 66; `go.sum` 8 → 350 lines |
| New CGO | none; all four targets build with `CGO_ENABLED=0` (RAN) |
| Verification time | about 3 ms of work, 11-13 ms per process, no network |
| Licences | Apache-2.0 / BSD / MIT only; needs a third-party notices file in releases |
| Trusted-root maintenance | one 6.8 KB file refreshed per release (automate with a scheduled PR); rotation about once or twice a year (inferred); a stale root fails new signatures closed |
| Library churn | sigstore-go v1.x, 4 minors in the 17 months since v1.0.0, plus upstream bumps in the 65-module graph that the owner's security-update process must absorb (compare: `cli` has 5 modules today) |
| Signing in CI | 1 workflow permission, one HTTP call for the token, about 40 lines with sigstore-go, a few seconds per push; public-instance availability SLO 99.5% (Rekor) |

## 5. Risks and unknowns

- **Size and dependency growth is the dominant cost** and the largest argument for "not
  yet": the CLI's whole supply-chain surface goes from 5 modules to 68 to verify one kind of
  signature. It is audited, widely used code, but it is a lot. Mitigations exist (build tag
  to compile verification out of dev builds; vendoring review) but were not tried.
- **Value depends on adoption.** The plan notes laptop pushes are the common case today;
  those stay unsigned, so initially almost nothing verifies. The feature pays off only if
  publishers move to CI publishing (D2's Action).
- **Not exercised on the exact shape**: no `messageSignature` bundle with a GitHub Actions
  certificate was available publicly; Actions policy was tested on a 2023 DSSE fixture. The
  identity code path is the same, but PR 1 should add a real capm-shaped fixture after the
  first real CI signing (or build a test CA emitting the Actions OIDs).
- **Signing path not run at all** (D is reading only): the Actions token fetch, Fulcio
  rate limits, Rekor v1 vs v2 selection and private-repository behaviour are all
  UNVERIFIED. The sigstore-go signing example itself defaults to *staging*.
- **Rekor v2 / new-key transition**: the current root already lists `log2025-1`; signing
  config still points at v1. When that flips, stale CLIs will reject new bundles (E4).
- **Library API stability** looks acceptable (v1.x for 18 months; I did not diff APIs
  between minors, UNVERIFIED), but release cadence has been uneven.
- **Login takeover is mitigated, not solved** (E1 limits).
- **Replay across versions** needs the manifest check (E1).
- **Privacy**: private-repo metadata and laptop emails become permanent and public (E5).
- **Trusted-root integrity at build time**: the root must come from the TUF client with a
  current TUF anchor; sigstore-go's own embedded TUF anchor is already expired
  (2026-06-22) and only works because the chain is walked online. A plain `curl` of the
  target is not equivalent.
- **No revocation**: a signed bundle verifies forever; only registry yank warns.

## 6. Proposed build plan (if proceeding)

PR 1 (the one to review first, no user-visible change):
`cli/internal/sigverify` with the embedded `trusted_root.json`, `Verify(bundle, digest, owner, pinnedOwnerID)`
returning the verified identity (issuer, owner URI, owner id, repo id, workflow ref,
run URL), the policy from E1, fixture bundles from the sources used here (a few files, tens of KB), the
`VirtualSigstore` tests, a test that the binary still builds `CGO_ENABLED=0` for the four
targets, a recorded size budget, a CI job that fails when the embedded root differs
from TUF's current root by more than N days, and a third-party notices file. `cli/go.mod` gains
one requirement. No command calls it yet.

Then, each its own PR:
2. Backend: `signatures` table, `PUT`/`GET /v1/bundles/{o}/{n}/{v}/signature`, write-once, owner only, 64 KiB cap, tests (as in the plan).
3. CLI `pull`/`run`/`inspect`: fetch the bundle if present, verify, manifest name/version check, pin the signing identity in `known.json`, downgrade rule, error messages, `--allow-...` override flag; label in `inspect` and `list`.
4. CLI `push --sign` for GitHub Actions only: ambient token, `sign.Bundle` with `PlainData`, upload, privacy notice, retry/non-fatal option.
5. D2 Action signs by default (or wraps `actions/attest`); docs replace "No signing" in `docs/security-notes.md`.
6. Website label; trusted-root refresh automation; later consider `CAPM_REQUIRE_SIGNED`.

## 7. Open questions for the owner

1. Is a CLI of about 21-24 MB (about 2.7x) and 68 linked modules acceptable? If not, the alternative is "not yet" (or a separate `capm-verify` helper), not a lighter library.
2. Confirm CI-only (no laptop signing) for v1, with interactive publishes permanently labelled `unsigned`.
3. Is "a workflow in any repository owned by this GitHub account" the right claim, or should publishers also pin a specific repository (repo id) on first signed publish?
4. Is publishing repository, commit, workflow path and run URL to a public log acceptable, including for private-repo publishers? Should signing stay opt-in (`--sign`)?
5. Should an owner who has published a signed version be allowed to publish an unsigned one later (downgrade rule E6 refuses by default)?
6. Is the registry's `ownerId` the GitHub account id for both user and organisation owners? (The CLI check relies on it matching `repository_owner_id`.)
7. Does the release process want a third-party notices file and a build tag to compile verification out of local dev builds?
8. Rekor v2 and Fulcio rotations will eventually break stale CLIs; is a fail-closed rule with a self-update hint acceptable, or do you want an opt-in online TUF refresh?

## 8. Owner decisions (Mason, 2026-11-13)

Answers to the six questions put to the owner after this spike. These are binding for the build.

1. **CLI size:** a CLI of roughly 21-24 MB is acceptable. Proceed with `sigstore-go`.
2. **Where signing happens:** CI only. Publishes from a laptop stay labelled `unsigned` permanently.
3. **What a signature binds to:** one specific repository, not "any repository the account owns". The verification policy must therefore check the certificate's repository identity (by numeric repository id, pinned on first use alongside the owner id) in addition to the owner and owner id.
4. **Public transparency log:** signing stays opt-in, because it publishes the repository, commit, workflow path and run link permanently, including for private repositories. The publisher must be told this before the first signature.
5. **Downgrade rule:** no. An owner who has published a signed version is NOT refused when a later version is unsigned. The CLI may say that an earlier version was signed and this one is not, but it does not block.
6. **Stale embedded trusted root:** refuse to verify and tell the user to update the CLI (`capm self-update`). No online TUF refresh.

Consequences for the build plan in section 6: step 3 drops the downgrade refusal (decision 5) and adds repository-id pinning (decision 3); step 4's signing is behind an explicit opt-in flag or action input with the privacy notice (decision 4).
