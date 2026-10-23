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
  Only the workflow's `publish` job requests them.

## Candidate validation

1. Merge the release candidate PR.
2. Confirm CI, CodeQL, Go security, GoReleaser snapshot, and native macOS
   artifact smoke checks are green.
3. Create and push an annotated `vMAJOR.MINOR.PATCH` tag (or
   `vMAJOR.MINOR.PATCH-PRERELEASE` for a prerelease) from the intended commit,
   or start the release workflow manually with an existing tag of that shape.
   The workflow rejects any other `v*` tag before it builds anything.
4. The read-only `verify` job runs first: the tests, the release fixtures, the
   unsigned reproducibility reference build, and the smoke tests that run the
   built binaries. Only when it passes does the `publish` job request the
   protected `release` environment; approve it then. That job rebuilds and
   signs on a fresh runner, refuses to continue unless its artifacts are
   byte-identical to the reference and the tag still names the commit `verify`
   tested, and then uploads to the draft release and attests.
5. Review the release evidence, then publish the GitHub draft from the release
   page. The smoke log and the generated cask are in the `verify` job's
   `speedns-release-smoke` artifact, and the signed asset list is in the
   `publish` job's `speedns-release-verification` artifact. Publishing
   triggers the Homebrew workflow; wait for that workflow to update
   `crypt0rr/homebrew-speedns` before testing `brew install`. It verifies the
   Sigstore signature on `checksums.txt` before generating the cask, skips
   prereleases without requesting approval, and refuses to replace a newer
   cask with an older release.
6. Confirm the published GitHub release, Debian packages, macOS archives,
   checksums, SBOMs, Cosign bundle, Homebrew cask update, and artifact
   attestations are present.

A release that adds a JSON report field must have vendored, in its candidate
PR, a report its own encoder writes with every optional section into
`internal/report/testdata/released/`, as `CONTRIBUTING.md` describes, so that
every later schema change is tested against what this release wrote.

## Verification

Download one archive together with `checksums.txt` and
`checksums.txt.sigstore.json`, then run the commands in the README's
“Verify a downloaded release” section in order: `cosign verify-blob` on
`checksums.txt` first, then the checksum of that one archive. Verify at least
one archive with the README's `gh attestation verify` command, which pins the
same signer identity as the cosign check, before announcing the release.

From v0.7.0 the SBOMs give the license of SpeeDNS's own Go module as
`NOASSERTION`. Syft now finds licenses in the local module cache only, and the
main module is never in it; earlier releases looked it up on the Go proxy. The
dependencies' licenses are still listed, and the `LICENSE` file in every
archive and the packages' license field are unchanged.

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

Release a backport by pushing its tag, or by a dispatch from `main` after the
cherry-pick, never by a dispatch started from the maintenance branch: that run
signs as `release.yml@refs/heads/<branch>`, which the documented Cosign and
attestation identity (a `v*` tag or `main`) rejects.

Since v0.7.0 the workflow builds the reference and the signed artifacts on two
runners and compares them byte for byte. `.goreleaser.yaml` supports that by
fixing the build host recorded in RPM headers, and
`scripts/reproducible-syft.sh` by keeping Syft offline. A dispatch from `main`
that releases an older tree uses that tree's `.goreleaser.yaml`, whose RPMs
record each runner's own host name, so the comparison fails on every RPM, and
whose SBOMs still use Syft's online enrichment, so a Go proxy lookup that fails
in only one of the builds stops the release as well. Cherry-pick the
`.goreleaser.yaml`, `scripts/artifact-smoke.sh` and
`scripts/reproducible-syft.sh` changes with the others, or push the tag, so
that its own single-job `release.yml` runs instead.
