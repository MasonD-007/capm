# Embedded trusted root: provenance

`trusted_root.json` is Sigstore's public-good trusted root, embedded with
`//go:embed`. It is the only source of trust for `sigverify`: the CA and log
keys it lists are the keys a signature is checked against. It is not fetched,
refreshed or cached at run time.

- source: https://tuf-repo-cdn.sigstore.dev, target `trusted_root.json`, fetched
  through the real TUF client (sigstore-go `pkg/tuf`, which verifies the root
  chain, timestamp, snapshot and targets metadata over the network) by
  `scripts/fetch-trusted-root.go`
- retrieved: 2026-11-14
- sha256: 6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66
- size: 6787 bytes
- format: `application/vnd.dev.sigstore.trustedroot+json;version=0.1`

The two lines above (`retrieved`, `sha256`) are rewritten by
`scripts/update-trusted-root.sh`; a test fails if the recorded hash does not
match the file. (Retrieved 2026-11-13 and again 2026-11-14 while testing the
script: the same sha256 both times.)

A plain `curl` of the target is NOT equivalent: the target is only trustworthy
once the TUF metadata that names its hash has been verified. Always refresh
with the script.

## Contents on the retrieval date

| kind | URL | valid from | valid until |
|---|---|---|---|
| Rekor log | rekor.sigstore.dev | 2021-01-12 | open |
| Rekor log | log2025-1.rekor.sigstore.dev | 2025-09-23 | open |
| Fulcio CA | fulcio.sigstore.dev | 2021-03-07 | 2022-12-31 |
| Fulcio CA | fulcio.sigstore.dev | 2022-04-13 | open |
| CT log | ctfe.sigstore.dev/test | 2021-03-14 | 2022-10-31 |
| CT log | ctfe.sigstore.dev/2022 | 2022-10-20 | open |
| Timestamp authority | timestamp.sigstore.dev | 2025-07-04 | open |

The same file (identical sha256) was examined by the signing spike
(`spike/signing/trusted_root.json`) on the same day.

## Refreshing

```
scripts/update-trusted-root.sh           # fetch, diff summary, rewrite file + the two lines above
scripts/update-trusted-root.sh --check   # report only; exit 1 if the embedded file differs
(cd cli && go test ./internal/sigverify/)
```

Needs network access to the public Sigstore TUF mirror and nothing else (no
credentials). Review the printed summary: an added log or CA is the normal
case; a removed or shortened one means older signatures may stop verifying.
