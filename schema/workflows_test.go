package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestWorkflowsParse fails if any GitHub Actions workflow is not valid YAML.
//
// Nothing in the tree parsed these files. A release workflow GitHub cannot read
// passes every gate and then fails at the worst possible moment -- after a tag
// is pushed, when the tag is already public and the module proxy may already
// have fetched it. The v0.1.0 release did fail at exactly that point for a
// different reason, and needed a manual re-dispatch.
//
// This asserts only that the documents parse and carry the keys Actions
// requires. It deliberately does not validate against a schema of the Actions
// language: that is a snapshot of a platform which changes without commits, and
// a linter pinned to yesterday's schema fails on correct workflows.
func TestWorkflowsParse(t *testing.T) {
	for _, workflowPath := range workflowPaths(t) {
		content, err := os.ReadFile(workflowPath)
		if err != nil {
			t.Fatalf("%s: %v", workflowPath, err)
		}
		var document map[any]any
		if err := yaml.Unmarshal(content, &document); err != nil {
			t.Fatalf("%s is not valid YAML, so GitHub cannot run it: %v", filepath.Base(workflowPath), err)
		}
		// "on" is a YAML 1.1 boolean, so some parsers key it as true rather
		// than as the string. Accept either spelling.
		_, named := document["on"]
		_, boolean := document[true]
		if !named && !boolean {
			t.Fatalf("%s has no trigger block, so it would never run", filepath.Base(workflowPath))
		}
		if _, ok := document["jobs"]; !ok {
			t.Fatalf("%s declares no jobs", filepath.Base(workflowPath))
		}
	}
}

// workflowStep, workflowJob and workflowFile hold only the fields the tests
// below read. The invariants are asserted on the parsed structure, never on
// the raw text: a substring check is satisfied just as well by a YAML comment
// or by an unrelated step's script.
type workflowStep struct {
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
}

type workflowJob struct {
	If    string         `yaml:"if"`
	Uses  string         `yaml:"uses"`
	Steps []workflowStep `yaml:"steps"`
}

type workflowFile struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

func workflowPaths(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no workflows found; the glob no longer matches the repository layout")
	}
	return paths
}

func readWorkflow(t *testing.T, workflowPath string) workflowFile {
	t.Helper()
	content, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var document workflowFile
	if err := yaml.Unmarshal(content, &document); err != nil {
		t.Fatalf("%s: %v", filepath.Base(workflowPath), err)
	}
	return document
}

func releaseWorkflow(t *testing.T) workflowFile {
	t.Helper()
	return readWorkflow(t, filepath.Join("..", ".github", "workflows", "release.yml"))
}

// stepsUsing returns every step, in any job, whose action is the one named.
func stepsUsing(document workflowFile, action string) []workflowStep {
	var steps []workflowStep
	for _, job := range document.Jobs {
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, action+"@") {
				steps = append(steps, step)
			}
		}
	}
	return steps
}

// withValue renders a `with:` input the way Actions passes it to the action:
// as text, so `fetch-depth: 0` and `fetch-depth: '0'` read alike. A missing or
// empty input renders as "<nil>", which matches nothing a test asks for.
func withValue(step workflowStep, input string) string {
	return fmt.Sprint(step.With[input])
}

// TestReleaseWorkflowFetchesFullHistory guards a specific way the release
// breaks late. release.yml chooses the previous stable tag by walking the tag
// list, and validates that the release tag points at the checked-out commit.
// Both need the tags, and GoReleaser builds the changelog from the history
// between them. actions/checkout fetches a shallow single commit with no tags
// unless told otherwise -- so a missing fetch-depth turns a correct workflow
// into one that silently picks the wrong range or aborts.
func TestReleaseWorkflowFetchesFullHistory(t *testing.T) {
	checkouts := stepsUsing(releaseWorkflow(t), "actions/checkout")
	if len(checkouts) == 0 {
		t.Fatal("release.yml has no actions/checkout step")
	}
	for _, step := range checkouts {
		if depth := withValue(step, "fetch-depth"); depth != "0" {
			t.Fatalf("release.yml checks out with fetch-depth %s, want 0; tag selection, tag validation and the changelog all need full history", depth)
		}
	}
}

// TestReleaseWorkflowDisablesGoCache keeps the signing job off shared caches.
// setup-go caches by default, and a tag or dispatch run can restore what
// main-branch CI, CodeQL or the scheduled live smoke saved. go mod verify
// checks only the module cache; GOCACHE entries are trusted as written, and
// both GoReleaser builds would read the same restored entries, so the
// reproducibility comparison cannot catch a planted one either.
func TestReleaseWorkflowDisablesGoCache(t *testing.T) {
	setups := stepsUsing(releaseWorkflow(t), "actions/setup-go")
	if len(setups) == 0 {
		t.Fatal("release.yml has no actions/setup-go step; update this test if Go is installed another way")
	}
	for _, step := range setups {
		if cache := withValue(step, "cache"); cache != "false" {
			t.Fatalf("release.yml sets up Go with cache %s; the signing job must set cache: false, since setup-go caches when it is omitted", cache)
		}
	}
}

// pinnedAction is a remote action or reusable workflow pinned to a full
// commit SHA. A tag or branch can be moved to different code after review; a
// SHA cannot, and a shortened one is ambiguous as the repository grows.
var pinnedAction = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@\s]+)?@[0-9a-f]{40}$`)

// TestWorkflowsPinActionsAndDeclarePermissions asserts two invariants every
// workflow meets today and nothing else enforces: Renovate pins digests but is
// not a gate. Every `uses:` is a local ./ path or pinned by full SHA, and every
// workflow declares top-level permissions, so no job silently inherits the
// repository's default token scope.
func TestWorkflowsPinActionsAndDeclarePermissions(t *testing.T) {
	references := 0
	for _, workflowPath := range workflowPaths(t) {
		name := filepath.Base(workflowPath)
		document := readWorkflow(t, workflowPath)
		for jobName, job := range document.Jobs {
			uses := []string{job.Uses}
			for _, step := range job.Steps {
				uses = append(uses, step.Uses)
			}
			for _, reference := range uses {
				if reference == "" {
					continue
				}
				references++
				if !strings.HasPrefix(reference, "./") && !pinnedAction.MatchString(reference) {
					t.Errorf("%s job %s uses %q; pin it to a full 40-character commit SHA", name, jobName, reference)
				}
			}
		}

		content, err := os.ReadFile(workflowPath)
		if err != nil {
			t.Fatal(err)
		}
		var topLevel map[string]any
		if err := yaml.Unmarshal(content, &topLevel); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// A bare `permissions:` parses as null and counts as undeclared here;
		// a workflow that needs no scopes says `permissions: {}`.
		if topLevel["permissions"] == nil {
			t.Errorf("%s declares no top-level permissions", name)
		}
	}
	if references == 0 {
		t.Fatal("no uses: references found; the workflow structure no longer matches this test")
	}
}

// TestWorkflowScriptsDoNotInterpolateExpressions keeps ${{ }} out of run:
// scripts. Actions substitutes an expression into the script text before the
// shell parses it, so a tag name, release title or dispatch input containing
// shell syntax would run as code. Values reach scripts through env: instead,
// where the shell sees them only as data.
func TestWorkflowScriptsDoNotInterpolateExpressions(t *testing.T) {
	for _, workflowPath := range workflowPaths(t) {
		for jobName, job := range readWorkflow(t, workflowPath).Jobs {
			for _, step := range job.Steps {
				if strings.Contains(step.Run, "${{") {
					t.Errorf("%s job %s interpolates an expression into a run: script; pass it through env: instead:\n%s",
						filepath.Base(workflowPath), jobName, step.Run)
				}
			}
		}
	}
}

// renovateCustomManager is the part of a renovate.json customManagers entry the
// test below exercises.
type renovateCustomManager struct {
	CustomType          string   `json:"customType"`
	ManagerFilePatterns []string `json:"managerFilePatterns"`
	MatchStrings        []string `json:"matchStrings"`
	DatasourceTemplate  string   `json:"datasourceTemplate"`
}

// managerFileMatches applies a Renovate managerFilePatterns entry, which is a
// regular expression when written as /.../ and a glob otherwise.
func managerFileMatches(t *testing.T, pattern, file string) bool {
	t.Helper()
	if len(pattern) > 1 && strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
		return regexp.MustCompile(pattern[1 : len(pattern)-1]).MatchString(file)
	}
	matched, err := path.Match(pattern, file)
	if err != nil {
		t.Fatalf("renovate.json managerFilePatterns %q: %v", pattern, err)
	}
	return matched
}

// goRunPin finds a tool a workflow runs straight from the module proxy.
var goRunPin = regexp.MustCompile(`go run (\S+)@(\S+)`)

// goRunModules names the module that provides each tool a workflow runs. The
// go datasource looks a dependency up as a module, so a custom manager that
// extracted the package path below the module root would find no releases.
var goRunModules = map[string]string{
	"honnef.co/go/tools/cmd/staticcheck": "honnef.co/go/tools",
}

// TestRenovateTracksWorkflowGoRunPins fails when a workflow runs a Go tool at a
// version Renovate cannot see. Its github-actions manager reads only uses:
// lines, so `go run module/cmd/tool@version` needs the custom manager in
// renovate.json -- and that manager feeds the go datasource, which knows only
// module versions. staticcheck stayed on 2025.1.1 from the day it was added,
// invisible to Renovate, because a release name never matches an update.
//
// Go's regexp is RE2, the engine Renovate prefers, and both read the named
// groups the same way, so the match below is the match Renovate makes.
func TestRenovateTracksWorkflowGoRunPins(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "renovate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		CustomManagers []renovateCustomManager `json:"customManagers"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		t.Fatalf("renovate.json: %v", err)
	}
	semver := regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

	pins := 0
	for _, workflowPath := range workflowPaths(t) {
		file := ".github/workflows/" + filepath.Base(workflowPath)
		for _, job := range readWorkflow(t, workflowPath).Jobs {
			for _, step := range job.Steps {
				for _, pin := range goRunPin.FindAllStringSubmatch(step.Run, -1) {
					pins++
					packagePath, version := pin[1], pin[2]
					if !semver.MatchString(version) {
						t.Errorf("%s runs %s@%s; pin it by module version (vX.Y.Z) so Renovate can update it", file, packagePath, version)
						continue
					}
					module, ok := goRunModules[packagePath]
					if !ok {
						t.Errorf("%s runs %s; add its module to goRunModules", file, packagePath)
						continue
					}
					if !renovateTracks(t, config.CustomManagers, file, pin[0], module, version) {
						t.Errorf("%s runs %s@%s, but no renovate.json go custom manager extracts module %s at %s from it",
							file, packagePath, version, module, version)
					}
				}
			}
		}
	}
	if pins == 0 {
		t.Fatal("no workflow runs a pinned Go tool; drop the renovate.json custom manager or update this test")
	}
}

// renovateTracks reports whether some go-datasource custom manager for file
// extracts module, at version, from text.
func renovateTracks(t *testing.T, managers []renovateCustomManager, file, text, module, version string) bool {
	t.Helper()
	for _, manager := range managers {
		if manager.CustomType != "regex" || manager.DatasourceTemplate != "go" {
			continue
		}
		applies := false
		for _, pattern := range manager.ManagerFilePatterns {
			applies = applies || managerFileMatches(t, pattern, file)
		}
		if !applies {
			continue
		}
		for _, matchString := range manager.MatchStrings {
			expression := regexp.MustCompile(matchString)
			match := expression.FindStringSubmatch(text)
			if match == nil {
				continue
			}
			if match[expression.SubexpIndex("depName")] == module &&
				match[expression.SubexpIndex("currentValue")] == version {
				return true
			}
		}
	}
	return false
}

// cosignIdentity is the signer identity argument of a cosign or gh attestation
// command, quoted in single quotes as README.md and the workflows write it.
var cosignIdentity = regexp.MustCompile(`--(?:certificate-identity-regexp|cert-identity-regex) '([^']+)'`)

// cosignIssuer is the certificate issuer argument of a cosign command.
var cosignIssuer = regexp.MustCompile(`--certificate-oidc-issuer[ =](\S+)`)

// githubActionsIssuer issues the OIDC tokens a GitHub-hosted workflow signs
// with, and so every SpeeDNS release signature's certificate.
const githubActionsIssuer = "https://token.actions.githubusercontent.com"

// TestHomebrewWorkflowVerifiesChecksumsBeforeTheCask guards the order that
// makes the Homebrew channel as trustworthy as the documented manual check.
// Every sha256 in the cask comes from the release's checksums.txt, an asset
// that can be replaced after the release job signed it. So the signature is
// verified, by the cosign build the release job signs with and against the
// identity README.md tells users to require, before the cask is generated.
// Prereleases are skipped at the job level, before the protected environment
// asks a reviewer to approve a run that could only fail.
func TestHomebrewWorkflowVerifiesChecksumsBeforeTheCask(t *testing.T) {
	homebrew := readWorkflow(t, filepath.Join("..", ".github", "workflows", "homebrew.yml"))
	job, ok := homebrew.Jobs["publish"]
	if !ok {
		t.Fatal("homebrew.yml has no publish job")
	}
	// The exact expression, not a mention of the field: the inverted
	// `if: ${{ github.event.release.prerelease }}` names it just as well and
	// would publish only prereleases.
	if job.If != homebrewSkipsPrereleases {
		t.Errorf("homebrew.yml publish job has if: %q, want %q so that prerelease events are skipped and dispatches are not",
			job.If, homebrewSkipsPrereleases)
	}

	installer, verify, generate := -1, -1, -1
	for index, step := range job.Steps {
		switch {
		case strings.HasPrefix(step.Uses, "sigstore/cosign-installer@") && installer < 0:
			installer = index
		case strings.Contains(step.Run, "cosign verify-blob") && verify < 0:
			verify = index
		case strings.Contains(step.Run, "scripts/homebrew-cask.sh") && generate < 0:
			generate = index
		}
	}
	if installer < 0 || verify < 0 || generate < 0 || installer >= verify || verify >= generate {
		t.Fatalf("homebrew.yml must install cosign, then verify checksums.txt, then generate the cask; got steps %d, %d, %d", installer, verify, generate)
	}
	if !strings.Contains(job.Steps[verify].Run, "checksums.txt.sigstore.json") {
		t.Errorf("homebrew.yml verifies checksums.txt without the release's Sigstore bundle")
	}

	releaseInstallers := stepsUsing(releaseWorkflow(t), "sigstore/cosign-installer")
	if len(releaseInstallers) == 0 {
		t.Error("release.yml no longer installs cosign with sigstore/cosign-installer; update this test")
	}
	for _, step := range releaseInstallers {
		if step.Uses != job.Steps[installer].Uses {
			t.Errorf("homebrew.yml verifies with %s but release.yml signs with %s; pin both to the same commit",
				job.Steps[installer].Uses, step.Uses)
		}
	}

	readme, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	documented := cosignIdentity.FindAllStringSubmatch(string(readme), -1)
	if len(documented) == 0 {
		t.Fatal("README.md documents no signer identity")
	}
	used := cosignIdentity.FindStringSubmatch(job.Steps[verify].Run)
	if used == nil {
		t.Fatal("homebrew.yml verifies checksums.txt without pinning the signer identity")
	}
	for _, identity := range documented {
		if identity[1] != used[1] {
			t.Errorf("README.md documents signer identity %q but homebrew.yml requires %q; the policies must match", identity[1], used[1])
		}
	}

	// cosign refuses a keyless bundle when no issuer is given, but the
	// identity regex alone says nothing about who issued the certificate.
	// Both halves of the policy are pinned, in README.md and here alike.
	documentedIssuers := cosignIssuer.FindAllStringSubmatch(string(readme), -1)
	usedIssuers := cosignIssuer.FindAllStringSubmatch(job.Steps[verify].Run, -1)
	if len(documentedIssuers) == 0 || len(usedIssuers) == 0 {
		t.Errorf("README.md and homebrew.yml must both pass --certificate-oidc-issuer %s; found %d and %d",
			githubActionsIssuer, len(documentedIssuers), len(usedIssuers))
	}
	for _, issuer := range append(documentedIssuers, usedIssuers...) {
		if issuer[1] != githubActionsIssuer {
			t.Errorf("cosign is told to accept certificates from issuer %q, want %q", issuer[1], githubActionsIssuer)
		}
	}
}

// homebrewSkipsPrereleases is the publish job's if:. The event-name clause
// admits dispatches, which carry no release payload.
const homebrewSkipsPrereleases = "${{ github.event_name != 'release' || !github.event.release.prerelease }}"

// homebrewConcurrencyGroup puts every run that can write the tap in one group
// and each prerelease event in a group of its own. Concurrency is resolved for
// the run before the publish job's if: skips a prerelease, so in the shared
// group that no-op run would take the single pending slot and cancel a stable
// run already waiting there. Compared exactly, because swapping the operands
// or dropping the event-name clause still mentions every part.
const homebrewConcurrencyGroup = "${{ (github.event_name == 'release' && github.event.release.prerelease) && " +
	"format('homebrew-prerelease-{0}', github.run_id) || 'homebrew-tap' }}"

// TestHomebrewWorkflowSerialisesTapWrites keeps two publications from
// interleaving their read and write of the tap's single cask, without letting
// a skipped prerelease run displace a stable one.
func TestHomebrewWorkflowSerialisesTapWrites(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "homebrew.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Concurrency struct {
			Group            string `yaml:"group"`
			CancelInProgress any    `yaml:"cancel-in-progress"`
		} `yaml:"concurrency"`
	}
	if err := yaml.Unmarshal(content, &document); err != nil {
		t.Fatalf("homebrew.yml: %v", err)
	}
	if document.Concurrency.Group != homebrewConcurrencyGroup {
		t.Errorf("homebrew.yml concurrency group is %q, want %q", document.Concurrency.Group, homebrewConcurrencyGroup)
	}
	// cancel-in-progress would let a newer release stop a publication part
	// way, after it wrote the tap but before it validated what it wrote.
	if cancel := fmt.Sprint(document.Concurrency.CancelInProgress); cancel != "false" {
		t.Errorf("homebrew.yml sets cancel-in-progress %s, want false", cancel)
	}
}

// releaseTagCheck extracts the expression a valid_release_tag() function
// matches, together with the C locale that keeps [0-9] to the ASCII digits.
var releaseTagCheck = regexp.MustCompile(`valid_release_tag\(\) \{\s*local LC_ALL=C\s*\[\[ "\$1" =~ (\S+) \]\]\s*\}`)

// TestReleaseTagShapeIsTheSameEverywhere keeps the copies of the release tag
// check from drifting apart. Each release script is standalone, so each
// carries its own valid_release_tag(), and release.yml checks the same shape
// before it builds. A copy that accepted more than the others would let a tag
// through one step that a later step, or the cask's Ruby string, then trips
// over.
func TestReleaseTagShapeIsTheSameEverywhere(t *testing.T) {
	sources := map[string]string{}
	scripts, err := filepath.Glob(filepath.Join("..", "scripts", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range scripts {
		content, err := os.ReadFile(script)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), "valid_release_tag()") {
			sources["scripts/"+filepath.Base(script)] = string(content)
		}
	}
	for _, step := range releaseWorkflow(t).Jobs["release"].Steps {
		if strings.Contains(step.Run, "valid_release_tag()") {
			sources[".github/workflows/release.yml"] = step.Run
		}
	}
	for _, required := range []string{
		".github/workflows/release.yml",
		"scripts/homebrew-cask.sh",
		"scripts/publish-homebrew-cask.sh",
		"scripts/validate-homebrew-tap.sh",
		"scripts/validate-published-release.sh",
	} {
		if _, ok := sources[required]; !ok {
			t.Errorf("%s no longer defines valid_release_tag(); update this test if the check moved", required)
		}
	}

	for source, content := range sources {
		match := releaseTagCheck.FindStringSubmatch(content)
		if match == nil {
			t.Errorf("%s defines valid_release_tag() without `local LC_ALL=C` and a single [[ =~ ]] test", source)
			continue
		}
		if match[1] != releaseTagShape {
			t.Errorf("%s checks release tags against %s, want %s", source, match[1], releaseTagShape)
		}
	}

	// The shape itself. Bash's ERE and Go's RE2 agree on this expression, so
	// these are the tags the scripts accept and refuse.
	shape := regexp.MustCompile(releaseTagShape)
	for _, tag := range []string{"v0.6.9", "v10.20.30", "v1.0.0-rc.1", "v1.0.0-beta-2"} {
		if !shape.MatchString(tag) {
			t.Errorf("release tag shape refuses %q", tag)
		}
	}
	for _, tag := range []string{"v0.7", "0.7.0", "v0.7.0 ", "v0.7.0;id", "v0.7.0#{`id`}", `v0.7.0";system("id");"`, "v1.0.0-rc_1", "v1.0.0-"} {
		if shape.MatchString(tag) {
			t.Errorf("release tag shape accepts %q", tag)
		}
	}
}

// releaseTagShape is vMAJOR.MINOR.PATCH[-PRERELEASE].
const releaseTagShape = `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`

// TestReleaseWorkflowExplainsAMissingTagSelectionScript covers a release
// that runs this workflow against an older tree. A dispatch runs release.yml
// from the branch it starts on but every script from the checked-out tag, and
// tags cut before scripts/previous-stable-tag.sh existed do not have it. The
// step must say so before it runs the script, not stop with a bare exit 127.
func TestReleaseWorkflowExplainsAMissingTagSelectionScript(t *testing.T) {
	const invocation = "bash scripts/previous-stable-tag.sh"
	const guard = "[[ ! -f scripts/previous-stable-tag.sh ]]"
	found := false
	for _, step := range releaseWorkflow(t).Jobs["release"].Steps {
		at := strings.Index(step.Run, invocation)
		if at < 0 {
			continue
		}
		found = true
		guarded := strings.Index(step.Run, guard)
		if guarded < 0 || guarded > at {
			t.Errorf("release.yml runs %s without first checking %s:\n%s", invocation, guard, step.Run)
		}
		if !strings.Contains(step.Run, "RELEASE_CHECKLIST.md") {
			t.Errorf("release.yml does not point a missing previous-stable-tag.sh at RELEASE_CHECKLIST.md:\n%s", step.Run)
		}
	}
	if !found {
		t.Fatal("release.yml no longer runs scripts/previous-stable-tag.sh; update this test")
	}
}
