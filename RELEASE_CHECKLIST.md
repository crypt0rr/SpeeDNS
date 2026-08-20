# SpeeDNS release checklist

This is the maintainer checklist for publishing a release. User installation
and verification instructions are in `README.md`.

## One-time repository setup

- Create a GitHub environment named `release`.
- Add required reviewers to that environment.
- Store `HOMEBREW_TAP_TOKEN` as an environment secret with write access only to
  `crypt0rr/homebrew-speedns`.
- Keep the release workflow's `GITHUB_TOKEN` and OIDC permissions enabled so
  GitHub artifact attestations and Cosign keyless signatures can be created.

## Candidate validation

1. Merge the release candidate PR.
2. Confirm CI, CodeQL, Go security, GoReleaser snapshot, and native macOS
   artifact smoke checks are green.
3. Create and push an annotated `v*` tag from the intended commit, or start the
   release workflow manually with an existing `v*` tag.
4. Approve the protected `release` environment when GitHub requests it.
5. Confirm the published GitHub release, Debian packages, macOS archives,
   checksums, SBOMs, Cosign bundle, Homebrew cask update, and artifact
   attestations are present.

## Verification

Download one archive together with `checksums.txt` and
`checksums.txt.sigstore.json`, then run the commands in the README's
“Verify a downloaded release” section. Verify at least one archive with
`gh attestation verify` before announcing the release.
