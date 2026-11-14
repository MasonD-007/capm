# Test fixtures: provenance

All four bundle files come from the sigstore-go module, version v1.4.0
(`github.com/sigstore/sigstore-go@v1.4.0/pkg/testing/data/bundles/`), copied
byte for byte from the Go module cache (checksum-verified by `go.sum`). That
repository is licensed under the Apache License 2.0; its LICENSE is reproduced
here as `LICENSE.sigstore-go` and the files are redistributed under it. They
are public test data.

| file | sha256 | what it is | used for |
|---|---|---|---|
| `sigstore.js@2.0.0-provenance.sigstore.json` | e88fe678350e86bce3275c6ecdfb27731dbe01756b42604ee8b0f4500932ff38 | A **real public-good Sigstore bundle with a GitHub Actions identity**: the SLSA provenance attestation for the npm package `sigstore@2.0.0`, signed 2023-08-18 by the `sigstore/sigstore-js` repository's `release.yml` workflow (owner id 71096353, repository id 495574555). Bundle media type v0.1; DSSE envelope with an in-toto statement whose subject digest is SHA-512 (`46d4e2f7...`); X.509 chain; Rekor v1 entry with inclusion proof, checkpoint and SET; Fulcio certificate with an embedded SCT. | The end-to-end tests of the real certificate chain, SCT, Rekor proof and SET, the signature check, and the identity policy against a real Actions certificate; tamper cases; fuzz seed. |
| `dsse-2sigs.sigstore.json` | 6603f237e113bbbae2d0132b8e74db79255c3b766503167b2b334533f119273c | A bundle from sigstore-go's test data (v0.1, with a certificate chain and a log entry) whose DSSE envelope carries two signatures. | "more than one signature is refused" |
| `public-key-validity.sigstore.json` | 572879eafedce8f93003c725452d335006d5565e0aaaaded82a157c2a5c355fa | A v0.3 bundle with public-key verification material and a message signature (no certificate, no log entry). | "public-key verification material is refused" |
| `LICENSE.sigstore-go` | c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4 | Apache License 2.0, from the sigstore-go module root. | licence for the three files above |

## Why the real Actions bundle is not a message signature

capm will sign tarball bytes (a `messageSignature` bundle, v0.3). No public
`messageSignature` bundle with a GitHub Actions identity was available from the
permitted sources (sigstore-go's own test data, Sigstore's public trusted root):
sigstore-go ships only this DSSE one. So the real bundle is verified through a
test-only verifier profile (SHA-512, DSSE allowed, older media types allowed;
everything else is the production code) and the production `Verify` is shown to
**refuse** it (`TestProductionRejectsFixture`). The message-signature shape is
covered end to end only with sigstore-go's in-memory fake Sigstore (which cannot
issue Actions-shaped certificates); see the package README for exactly which
combinations that leaves untested on a real message-signature bundle.

## `fuzz/FuzzVerify/`

Go's fuzz corpus. `e354b33fab5405dd` is the one input the fuzzer found that
verified although it differed from the fixture: the *name* on the Rekor
checkpoint's signature line (`<em dash> <name> <base64>`) was changed. That name
is a label, not authenticated by anything (the signature after it is verified
against the log key from the trusted root), so this is harmless malleability,
and the fuzz oracle now normalises it. The file is kept as a regression seed.

## Derived cases

Negative cases (tampered signature, certificate, inclusion proof, SET, log
entry body, payload, integrated time; removed or duplicated log entries;
changed media type; truncated/modified trusted roots) are generated in the
tests from the real bundle, not stored.
