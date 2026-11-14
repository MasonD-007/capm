# sigverify

Offline verification that a downloaded bundle tarball was signed by a specific
GitHub Actions workflow, using Sigstore keyless signatures.

```go
id, err := sigverify.Verify(sigBundle, sha256OfTarball, sigverify.Expect{OwnerLogin: "acme"})
```

**Status: nothing calls this yet.** It is step 1 of bundle signing (see
`docs/signing-findings.md` on the `spike/signing` branch, sections 3, 6 and 8).
There is no user-visible change, no `main`-package import, and the shipped CLI
binary is byte-for-byte the same size as before. User docs
(`docs/security-notes.md`, "No signing") are deliberately unchanged.

## What a successful `Verify` guarantees

A nil error means all of these held, using only data in the bundle and the
trusted root compiled into this binary:

1. The bundle is the one accepted shape: media type v0.3, a single message
   signature (not a DSSE/in-toto attestation), Fulcio **certificate**
   verification material (not a public key), exactly one transparency-log entry.
2. The signing certificate chains to a Fulcio CA in the embedded root, was valid
   at the log's integrated time, and carries a valid SCT from an embedded CT log.
3. The Rekor entry's inclusion proof and signed entry timestamp verify against a
   Rekor log key in the embedded root, and its integrated time is not in the
   future (10 minutes of clock skew allowed).
4. The signature is over exactly the 32-byte SHA-256 `digest` you passed.
5. The identity policy below holds, on the **verified** certificate.

`Identity` is then safe to display and to pin: every string in it has the shape
of a GitHub value (login, `owner/repo`, workflow URL, 40/64-hex commit, Actions
run URL); a field that fails its shape is refused if it is part of the policy,
or left empty if it is informational (`SourceSHA`, `RunURL`). Free-text fields
(`SourceRef`, the ref in `WorkflowRef`) are restricted to printable ASCII and
200 bytes.

## What it does not guarantee

- **Not "this is the version you asked for".** The signature covers bytes, not
  `owner/name@version`. A caller must compare the manifest inside the verified
  tarball (name, version) with what it requested, or an old signed tarball can be
  replayed under a new label. (The spike found `pull` and `run` do not do this
  today.)
- **Not a particular workflow, branch or reviewer.** It proves some workflow run
  in the named repository signed the digest. Anyone who can run a workflow there
  can sign. Pinning a workflow path or ref is a possible later tightening; the
  SAN and `WorkflowRef` are exposed for it.
- **No revocation.** A bundle that verified once verifies forever (as of the
  trust root in the binary). The log's integrated time, not `now`, is the clock
  for the 10-minute certificate.
- **Login takeover is mitigated, not solved.** Pinning `OwnerID` and
  `RepositoryID` (below) stops a re-registered login from passing *after* the
  first use on that machine; it cannot help the first use.
- **Public-good Sigstore only.** No custom Fulcio/Rekor, no GitHub-operated
  Fulcio (so no attestations for private repositories made with GitHub's own
  instance), no TSA-only timestamps, no DSSE attestations.
- **A forged bundle and a bundle from a newer Sigstore look alike when the
  trust root is old.** See "Stale trust root".

## Policy

All rows are enforced by `checkIdentity` (`policy.go`) on the verified
certificate. "Required" means a certificate lacking it is refused even when the
caller did not ask to compare it.

| # | Rule | Source in the certificate | Compared with |
|---|---|---|---|
| 1 | Issuer is exactly `https://token.actions.githubusercontent.com` | Fulcio issuer extension (1.3.6.1.4.1.57264.1.8 or the legacy .1; sigstore-go keeps whichever appears last in the certificate) | constant |
| 2 | Owner URI is exactly `https://github.com/<login>`, a valid GitHub login, nothing after it | `SourceRepositoryOwnerURI` (.16) | `Expect.OwnerLogin`, ASCII case-insensitive. `acme` does not match `acme-evil`, `acme/evil`, `acm`, `http://...`, other hosts |
| 3 | Owner id present, canonical positive decimal | `SourceRepositoryOwnerIdentifier` (.17) | `Expect.OwnerID` if non-zero |
| 4 | Source repository URI is exactly `https://github.com/<owner>/<repo>`, valid names, owner equals the owner URI's login | `SourceRepositoryURI` (.12) | `Expect.Repository` if non-empty, ASCII case-insensitive |
| 5 | Repository id present, canonical positive decimal | `SourceRepositoryIdentifier` (.15) | `Expect.RepositoryID` if non-zero |
| 6 | SAN is a workflow reference `https://github.com/<o>/<r>/.github/workflows/<file>.y[a]ml@<ref>`; build signer URI (.9), if present, likewise | SAN, `BuildSignerURI` | nothing: required to be well formed only |

Why the extensions and not the SAN for owner and repository: the SAN is the
`job_workflow_ref`, the repository that holds the *workflow file*. With a
reusable workflow (the planned capm publish Action) that is the Action's
repository, not the publisher's, while .12/.16 still name the repository that
ran it. Row 6 therefore does not compare the SAN with anything; it only requires
that an Actions certificate looks like one, so a malformed or non-Actions SAN is
refused and `WorkflowRef` is safe to show. `Identity.WorkflowRef` is the build
signer URI when present, else the SAN.

`Expect.OwnerLogin` must itself be a valid GitHub login (ASCII; so Unicode case
folding such as U+212A cannot make `K` equal `k`); `Expect.Repository`, when set,
must be `owner/repo` for the same owner. Violations are `ErrInvalidInput`.

## Errors

`errors.Is` against: `ErrInvalidInput` (bad arguments, digest not 32 bytes),
`ErrMalformed` (not the accepted bundle shape, over 64 KiB, unparseable),
`ErrUntrusted` (a crypto or log check failed, wrong digest, clock), `ErrIdentity`
(`*IdentityError` says which `Field` and whether it was `mismatch`, `missing` or
`malformed`), `ErrStaleTrustRoot` (`*StaleTrustRootError`). The library's own
error is wrapped (reachable with `errors.Unwrap`) but `Error()` prints it
sanitised (printable ASCII, 200 bytes); `IdentityError` shows a certificate value
only if it has a legitimate GitHub shape.

`Verify` recovers a panic inside a dependency and reports `ErrMalformed`.

## Stale trust root

The trusted root has no expiry of its own; it is a list of logs and CAs with
validity windows. Before any cryptography, `checkCoverage` returns
`*StaleTrustRootError` (`errors.Is(err, ErrStaleTrustRoot)`) when this build's
root cannot speak to the signature:

- no Rekor log or no Fulcio CA in the root is valid *today* (the root has aged out), or
- the entry names a Rekor log key the root does not list (Sigstore added or rotated a log), or
- the leaf certificate's issuer matches no CA root or intermediate in the root (Fulcio rotated).

Anything else (a window that excludes the signing time, a bad proof) is
`ErrUntrusted`. A caller should turn `ErrStaleTrustRoot` into "this capm's built-in
Sigstore trust data does not cover this signature; update capm (`capm
self-update`)". It must remain a refusal, never a fall-back to "unsigned": offline,
"Sigstore rotated after this build" and "signed under a CA this build never
trusted" cannot be told apart. The spike found that older roots keep verifying
signatures made under keys they know, so staleness bites only for *new* keys.
Tested in `TestStaleTrustRoot` (truncated: no logs, no CAs; only the newer log;
only the retired CA; every window ended) and `TestStaleByCurrentTime`.

## Trusted root

`trusted_root.json` is Sigstore's public-good trusted root, embedded with
`//go:embed`. Provenance (source, date, sha256) is in `TRUSTED_ROOT.md`;
`scripts/update-trusted-root.sh` refreshes it through the real TUF client and
prints which logs and CAs changed (`--check` only reports); a test fails if the
recorded sha256 does not match the file, and another if the embedded root has no
currently valid Fulcio CA, Rekor log and CT log.

**Scheduled freshness check (design only; no workflow is added by this change).**
A weekly workflow (and `workflow_dispatch`) on `main` would:

1. run `scripts/update-trusted-root.sh --check` (public network only, no secrets);
2. if it exits 1, run the script without `--check`, run `go test ./internal/sigverify/`
   in `cli`, and open a pull request with the diff summary in the body (use a
   token or GitHub App that can trigger CI on the PR; a PR opened with the default
   `GITHUB_TOKEN` does not start workflows);
3. independently, fail the job when any current entry of the embedded root has an end
   date within 60 days (`TestEmbeddedRootIsCurrent` already fails the day one
   expires; the lead time is the point);
4. be ignored for releases: a release should simply build from whatever is on `main`.

Cadence: Sigstore's root content changed about once or twice in the year the spike
looked at (inferred from validity windows); weekly is cheap and bounds the age of
a release's root to about a week plus review time.

## Offline guarantee, and the TUF client

`Verify` does no I/O: the package imports no `net`, `net/http`, `os` or `os/exec`
(`TestNoNetworkImports`), and `TestVerifyIsOffline` runs success and every failure
path with the default HTTP transport, client and resolver replaced by ones that
record an attempt (and checks the guard fires on a deliberate request).

**The TUF client is in the dependency graph but not in the binary.**
`sigstore-go`'s `verify` package imports `pkg/root`, which imports `pkg/tuf` (and
so `go-tuf/v2`) for `FetchTrustedRoot`/`NewLiveTrustedRoot`. Loading the root from
embedded JSON (`root.NewTrustedRootFromJSON`) is in that same package, and the
`root.TrustedMaterial` interface cannot be implemented without it, so the
dependency cannot be avoided without forking the library. `go list -deps` shows
six go-tuf/`pkg/tuf` packages; but nothing reachable from `Verify` calls them, and
the linker drops them: an unstripped CLI build that calls `Verify` contains **zero**
symbols from `go-tuf` or `sigstore-go/pkg/tuf` (checked with `go tool nm`). Their
cost is therefore in `go.sum` and module count, not in the binary. gRPC, protobuf,
go-openapi, the Rekor client, OpenTelemetry, klog and certificate-transparency-go
packages *are* linked (they are what `pkg/verify` and `pkg/tlog` import) and
account for most of the size below.

## Size budget

Release flags (`CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=..."`),
Go 1.27.4, measured 2026-11-13/14 with sigstore-go v1.4.0:

| target | CLI before this change | CLI after this change (not referenced) | projected: CLI that calls `Verify` | growth |
|---|---:|---:|---:|---:|
| darwin/arm64 (host) | 7,885,426 | 7,885,426 | 19,230,754 | +11.3 MB (+144%) |
| linux/amd64 | 8,417,440 | 8,417,440 | 19,931,296 | +11.5 MB (+137%) |
| darwin/amd64 | | | 20,495,312 | |
| linux/arm64 | | | 18,612,384 | |

The projection was measured by temporarily adding an uncommitted file to the
`main` package that references `sigverify.Verify` (reachable from `init`), building
the four targets, and deleting it. It is therefore the real CLI plus the verifier,
about 19-20.5 MB, below the spike's 21-24 MB estimate (the owner accepted 21-24).
The "after, not referenced" column has the same byte count as "before", but the
content differs because adding the dependency raised `golang.org/x/sys` to v0.49.0
and `golang.org/x/term` to v0.47.0 (which sigstore-go requires); sizes are identical
to the byte. Dependency growth: `cli/go.sum` 8 to 359 lines; `go list -m all`
(`GOWORK=off`) 6 to 378 modules; `go.mod` requirements 4 to about 69; 4 to 69
modules in the linked binary that calls `Verify`.

## Tests, and what is covered where

`go test ./internal/sigverify/` takes about 0.5 s (2.2 s with `-race`). The fuzz
target does not run by default (plain `go test` replays its seed corpus):

    go test -fuzz=FuzzVerify -fuzztime=30s ./internal/sigverify/

The four-target `CGO_ENABLED=0` compile (`TestBuildsWithoutCGOForReleaseTargets`)
runs when `CI` is set or `SIGVERIFY_CROSS_BUILD=1` (about 20-25 s with a warm
cache, longer cold); skipped with `-short`.

There is **no public message-signature bundle with a GitHub Actions identity**
available offline; the only real Actions bundle (sigstore-go test data) is a v0.1
DSSE attestation with a SHA-512 subject. So:

| Behaviour | Real Actions bundle, test-only profile (SHA-512, DSSE, v0.1 allowed; same verifier code otherwise) | Fake Sigstore (`VirtualSigstore`), production message-signature shape | `checkIdentity` on certificate values only |
|---|:-:|:-:|:-:|
| Chain to Fulcio root, SCT, Rekor proof + SET, signature over digest | yes | chain, proof, SET, signature (the fake CA issues no SCT, so SCT is not required there) | |
| Wrong digest; tampered signature, certificate, inclusion proof, SET, log entry, payload, integrated time; no log entry | yes (each refused) | wrong digest | |
| Right owner; wrong owner; prefix/suffix/path tricks; case; wrong owner id; wrong repository id; wrong repository | yes (`TestRealBundlePolicy`) | | yes |
| Issuer other than Actions | | yes (fake cert, real policy) | yes |
| Missing/zero/negative/non-canonical/overflowing ids; malformed owner and repository URIs (http, host tricks, userinfo, trailing slash, newline, non-ASCII); SAN not a workflow reference; reusable workflow in another org accepted; informational-field shape checks; no echo of attacker text | | | **only here** |
| Rejects: two signatures, public-key material, unknown media type, two log entries, empty/garbage/oversize input, bad digest length | yes | yes (DSSE, wrong version) | |
| Stale trust root (several kinds), future-dated log time | yes | unknown CA / unknown log | |
| Production `Verify` entry point with a successful result | **not run end to end** (no suitable bundle); `verifyEntity` is exactly what it calls, and the production profile is refused on the fixture | | |

Be aware of the last row: the accept path of the exported `Verify` with the
production profile (v0.3 message signature, SCT required, embedded root, Actions
identity) has never been exercised against a real bundle. The first real CI
signing (step 4 of the plan) must add that fixture before step 3 relies on it.

The tamper tests are caught, as the spike found, mostly at the transparency-log
check (the log entry commits to the signature and certificate); the digest case
exercises the signature check itself. `FuzzVerify` asserts no panic and no success except for the fixture itself
(compared as parsed protobufs, so whitespace and key order do not count). Runs after
the oracle fix: 30 s, 209,353 executions, and 60 s, 17,398 executions (the rate is
very uneven because mutated bundles that reach the Merkle/crypto checks are slow),
no failure either time. The first 30 s run found one benign malleability (the name on a Rekor checkpoint signature line is not
authenticated; see `testdata/README.md`).

## Fixtures

`testdata/README.md` gives the provenance and licence of each file.

## Third-party notices

`cli/THIRD_PARTY_NOTICES.md` is generated by `scripts/gen-notices.sh` for every
module the CLI can link (68 today: Apache-2.0, BSD-2/3-Clause, MIT, some with
mixed or header-only Apache notices; no unrecognised licence). A test fails if
`cli/go.mod`, `cli/go.sum` or `go.work` changed since it was generated;
`scripts/gen-notices.sh --check` does the full regeneration. **Not yet attached to
releases.** Follow-up: have `cli-release.yml` (and the per-commit job in
`release.yml`) upload it next to `checksums.txt`, and mention it in the install
script/Homebrew formula; that changes the release workflow, so it is its own PR.

## What later steps must do

1. **Pin ids.** After the first successful `Verify` for `registry+owner/name`,
   store `Identity.OwnerID` (the `ownerId` field already in `known.json`) and
   `Identity.RepositoryID`, and pass them back in `Expect` on later runs. Refuse
   when they differ; refuse when the registry's reported owner id disagrees with
   the certificate's. Treat a changed repository id as an escalation, not a
   warning. (Confirm the registry's `ownerId` and the certificate's
   `repository_owner_id` are the same id space; unverified.)
2. **Check the manifest.** Compare the manifest inside the verified tarball
   (name, version) with what `pull`/`run` asked for, and the manifest's
   repository (if it names one) with `Expect.Repository`. The signature binds
   only bytes.
3. **Use the CLI's own digest.** Pass the SHA-256 of the tarball bytes the CLI
   downloaded (`cmd_pull.go` already computes it as `sha256:<hex>`; strip the
   prefix and decode), not the registry's reported digest.
4. **Map errors.** `ErrStaleTrustRoot` to "update capm"; `ErrIdentity` shows
   `Field`; `ErrUntrusted`/`ErrMalformed` are hard errors for a bundle that
   *has* a signature. A bundle with no signature is a separate, earlier decision
   (owner decision: no downgrade refusal; the CLI may say an earlier version was
   signed).
5. **Privacy notice.** Signing writes the repository, owner id, workflow path,
   ref, commit SHA and Actions run URL to the public Rekor log permanently, for
   private repositories too. The publisher must be told before the first
   signature (opt-in signing).
6. **Keep the root fresh.** Merge the weekly refresh PR and ship it; add the scheduled
   check designed above.
7. **Add a real fixture.** After the first real CI signing add a message-signature
   bundle with an Actions certificate and a test for the exported `Verify`
   accept path.
