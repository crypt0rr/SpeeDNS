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
3. Create and push an annotated `vMAJOR.MINOR.PATCH` tag (or
   `vMAJOR.MINOR.PATCH-PRERELEASE` for a prerelease) from the intended commit,
   or start the release workflow manually with an existing tag of that shape.
   The workflow rejects any other `v*` tag before it builds anything.
4. Approve the protected `release` environment when GitHub requests it.
5. Review the generated release evidence, then publish the GitHub draft from
   the release page. Publishing triggers the Homebrew workflow; wait for that
   workflow to update `crypt0rr/homebrew-speedns` before testing `brew install`.
   It verifies the Sigstore signature on `checksums.txt` before generating the
   cask, skips prereleases without requesting approval, and refuses to replace
   a newer cask with an older release.
6. Confirm the published GitHub release, Debian packages, macOS archives,
   checksums, SBOMs, Cosign bundle, Homebrew cask update, and artifact
   attestations are present.

## Verification

Download one archive together with `checksums.txt` and
`checksums.txt.sigstore.json`, then run the commands in the README's
“Verify a downloaded release” section in order: `cosign verify-blob` on
`checksums.txt` first, then the checksum of that one archive. Verify at least
one archive with the README's `gh attestation verify` command, which pins the
same signer identity as the cosign check, before announcing the release.

## Backport releases

A stable release cut from a maintenance branch after a newer stable release
(say v0.5.3 after v0.6.1) gets release notes from the previous stable tag
below it, v0.5.2. Its Homebrew run fails rather than move the tap back to the
older version. To publish an older release to the tap deliberately, for example
after withdrawing a newer one, run the Homebrew workflow manually with the tag
and `allow_downgrade` selected.

The release workflow runs the scripts in the tag's own tree. A tag push also
runs the tag's own `release.yml`; a dispatch runs `release.yml` from the branch
it is started on, but still checks the tag out. The previous-tag choice above
arrived in v0.6.9, so a maintenance branch cut before v0.6.9 must first
cherry-pick it: the "Select the previous tag for release notes" step in
`release.yml` and `scripts/previous-stable-tag.sh`. Without them, a tag push
still measures the notes from the highest stable tag overall (v0.6.1..v0.5.3),
and a dispatch from `main` fails at that step because the tag has no
`scripts/previous-stable-tag.sh`. A dispatch from `main` that re-runs any
stable tag up to v0.6.8 fails at the same step, for the same reason.
