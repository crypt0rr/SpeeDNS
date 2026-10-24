package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
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
	ID               string         `yaml:"id"`
	Name             string         `yaml:"name"`
	Uses             string         `yaml:"uses"`
	Run              string         `yaml:"run"`
	Shell            string         `yaml:"shell"`
	WorkingDirectory string         `yaml:"working-directory"`
	With             map[string]any `yaml:"with"`
	Env              map[string]any `yaml:"env"`
}

type workflowJob struct {
	If          string            `yaml:"if"`
	Uses        string            `yaml:"uses"`
	RunsOn      any               `yaml:"runs-on"`
	Needs       any               `yaml:"needs"`
	Environment any               `yaml:"environment"`
	Permissions any               `yaml:"permissions"`
	Env         map[string]any    `yaml:"env"`
	Defaults    workflowDefaults  `yaml:"defaults"`
	Outputs     map[string]string `yaml:"outputs"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowFile struct {
	Permissions any                    `yaml:"permissions"`
	Env         map[string]any         `yaml:"env"`
	Defaults    workflowDefaults       `yaml:"defaults"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

// workflowDefaults is a defaults: block, at the workflow or the job level. It
// gives the shell and the working directory of every run: step that does not
// set its own.
type workflowDefaults struct {
	Run struct {
		Shell            string `yaml:"shell"`
		WorkingDirectory string `yaml:"working-directory"`
	} `yaml:"run"`
}

// workflowPaths lists every workflow file GitHub runs. It runs .yaml files in
// .github/workflows as well as .yml ones, so a test that read only one
// spelling would let a new workflow escape every invariant below by its name.
func workflowPaths(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join("..", ".github", "workflows", pattern))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
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

// TestReleaseWorkflowDisablesGoCache keeps both release builds off shared
// caches. setup-go caches by default, and a tag or dispatch run can restore
// what main-branch CI, CodeQL or the scheduled live smoke saved. go mod verify
// checks only the module cache; GOCACHE entries are trusted as written, and
// the reference and the signed build would both read the same restored
// entries, so the reproducibility comparison cannot catch a planted one.
func TestReleaseWorkflowDisablesGoCache(t *testing.T) {
	setups := stepsUsing(releaseWorkflow(t), "actions/setup-go")
	if len(setups) == 0 {
		t.Fatal("release.yml has no actions/setup-go step; update this test if Go is installed another way")
	}
	for _, step := range setups {
		if cache := withValue(step, "cache"); cache != "false" {
			t.Fatalf("release.yml sets up Go with cache %s; every release job must set cache: false, since setup-go caches when it is omitted", cache)
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
// that can be replaced after release.yml's publish job signed it. So the
// signature is verified, by the cosign build that job signs with and against
// the identity README.md tells users to require, before the cask is generated.
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
	for jobName, job := range releaseWorkflow(t).Jobs {
		for index, step := range job.Steps {
			if strings.Contains(step.Run, "valid_release_tag()") {
				// Keyed per step: two release.yml steps defining the function
				// must both be checked, not only the last one seen.
				sources[fmt.Sprintf(".github/workflows/release.yml (job %s, step %d)", jobName, index+1)] = step.Run
			}
		}
	}
	for _, required := range []string{
		".github/workflows/release.yml",
		"scripts/homebrew-cask.sh",
		"scripts/publish-homebrew-cask.sh",
		"scripts/validate-homebrew-tap.sh",
		"scripts/validate-published-release.sh",
	} {
		found := false
		for source := range sources {
			found = found || source == required || strings.HasPrefix(source, required+" (job ")
		}
		if !found {
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
	for _, job := range releaseWorkflow(t).Jobs {
		for _, step := range job.Steps {
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
	}
	if !found {
		t.Fatal("release.yml no longer runs scripts/previous-stable-tag.sh; update this test")
	}
}

// grantsWrite reports whether a permissions block gives the token write
// access to scope, or to any scope when scope is empty. write-all grants all.
func grantsWrite(permissions any, scope string) bool {
	switch value := permissions.(type) {
	case string:
		return value == "write-all"
	case map[string]any:
		for name, level := range value {
			if (scope == "" || name == scope) && fmt.Sprint(level) == "write" {
				return true
			}
		}
	}
	return false
}

// jobPermissions is what a job's token may do: the job's own permissions
// block when it has one, the workflow's otherwise.
func jobPermissions(document workflowFile, job workflowJob) any {
	if job.Permissions != nil {
		return job.Permissions
	}
	return document.Permissions
}

// jobNeeds lists the jobs a job waits for; needs: takes a name or a list.
func jobNeeds(job workflowJob) []string {
	switch value := job.Needs.(type) {
	case string:
		return []string{value}
	case []any:
		names := make([]string, 0, len(value))
		for _, name := range value {
			names = append(names, fmt.Sprint(name))
		}
		return names
	}
	return nil
}

// environmentName reads environment: in either of its two spellings.
func environmentName(environment any) string {
	switch value := environment.(type) {
	case string:
		return value
	case map[string]any:
		if name, ok := value["name"].(string); ok {
			return name
		}
	}
	return ""
}

// signingJobTools are what a job able to mint OIDC tokens must not run
// because they execute the project's tests or its dependencies' code: go
// test, go run, go generate, go tool, the coverage gate, the release fixture,
// and artifact-smoke.sh, which runs the built binaries.
const signingJobTools = `\bgo\s+(?:test|run|generate|tool)\b|` +
	`scripts/(?:coverage|artifact-smoke|release-fixture)\.sh`

// signingJobBuildOutput matches a path into what GoReleaser built, wherever it
// is written: in a script, an env: value or a working directory alike.
//
//   - GoReleaser's per-target build directory, speedns_<os>_<arch>..., which
//     catches cd dist && ./speedns_linux_amd64_v1/speedns. A release file
//     name has the version, which always holds a dot, where a build
//     directory has the OS, so the archives and packages do not match;
//   - any path into a subdirectory of dist/, such as the glob dist/*/speedns;
//   - the binary's own name, speedns or speedns.exe, or {{ .Name }}, which
//     GoReleaser sets to it in a build hook, ending a path behind dist, ., ..,
//     ~, the glob *, a quote, a variable, a template or a $(command), which
//     catches for b in */speedns run inside dist/,
//     "${dir}/${target}/speedns", bin=dist/speedns; "${bin}" and a hook's
//     cd "$(dirname "{{ .Path }}")" && ./{{ .Name }}. The Go package
//     ./cmd/speedns, the cask dist/speedns.rb and
//     ${RUNNER_TEMP}/speedns-repro-reference do not match.
//
// These refuse reading those paths as well as running them. That costs
// nothing: a signing job compares, uploads and attests only what sits at the
// top of dist/ (archives, packages, SBOMs, checksums.txt, the changelog), and
// once a path is in a variable nothing tells an argument from a command.
const signingJobBuildOutput = `\bspeedns_[a-z0-9]+_|` +
	`\bdist/[^\s/"';|&)]+/|` +
	`(?:[*}).~"']|\bdist|\$\w+)/(?:speedns(?:\.exe)?(?:$|[\s"';|&)\x60])|\{\{[^}]*\.Name\b[^}]*\}\})`

// shellPathPart is one part of a path as a script writes it, between slashes:
// ~, a variable, an Actions expression, a GoReleaser template, a $(command) or
// a plain name such as . or .., quoted or not.
const shellPathPart = `["']?(?:~|\$\{\{[^}]*\}\}|\{\{[^}]*\}\}|\$\{[^}]*\}|\$\w+|\$\([^)]*\)|[\w.-]+)["']?`

// goreleaserBuiltBinary is a GoReleaser template that reads .Path, quoted or
// not. In a build hook, .Path is the binary the build has just made, such as
// dist/speedns_linux_amd64_v1/speedns, so {{ .Path }} where a command starts
// runs it.
const goreleaserBuiltBinary = `["']?\{\{[^}]*\.Path\b[^}]*\}\}`

// signingJobForbidden matches what a job able to mint OIDC tokens must not
// run, in a run: script as shellCode leaves it, in a shell: or in any string
// of .goreleaser.yaml. That is signingJobTools, signingJobBuildOutput, and
//
//   - a dist/ path where a command starts: at the start of a line; after one
//     of ; & | { ! or a backtick; after a ( that opens no array, as x=( and
//     x+=( do; after if, elif, then, else, do, while or until; or after
//     exec, command, time, nohup, sudo, env, xargs, bash or sh and any of
//     their options written as single words that begin with -. VAR=value
//     assignments may come first, the value bare, quoted or a substitution.
//     The path may have parts in front of dist/, each a name, ., .., ~, a
//     variable, an expression, a template or a $(command), quoted or not, so
//     ./dist/..., ../../dist/..., ~/work/dist/...,
//     /srv/work/SpeeDNS/dist/..., "${GITHUB_WORKSPACE}/dist/...",
//     "${{ github.workspace }}/dist/...", "$(pwd)/dist/..." and
//     {{ .Env.GITHUB_WORKSPACE }}/dist/... all count;
//   - goreleaserBuiltBinary where a command starts, as above. A GoReleaser
//     build hook that runs it, as {{ .Path }} version and
//     sh -c 'test "{{ .Os }}" != linux || {{ .Path }} version' do, runs the
//     binary in the job that signs, while
//     ./scripts/normalize-build-mtime.sh {{ .Path }} only hands it to a
//     script. Each string of .goreleaser.yaml starts as a line does, so a
//     hook's dir: of {{ dir .Path }} is refused as well;
//   - find -exec, -execdir, -ok or -okdir with the found file itself, {} or
//     ./{}, as the command;
//   - a find test that picks the binary by its name: -name, -iname, -path,
//     -ipath, -wholename or -iwholename with speedns or speedns.exe, in any
//     case, alone or ending a path. Whatever then runs what find lists,
//     xargs, a variable or -exec sh -c, is out of the pattern's sight, so,
//     as with the build output, a find that lists the binary only to hash
//     it is refused as well. A find for other names, such as
//     -name 'speedns_*.deb', passes.
//
// A top-level dist/ file passes as an argument of any command but the
// wrappers above, whether on that command's line, on a continuation line or
// inside a $(command), as an item of an array written on one line, and as a
// redirection target, as the publish job's hashing and uploads need. Where a
// dist/ path stands where a command could start, the pattern cannot tell a
// read from a run, so it refuses those reads as well: an array or a
// here-document written one item per line, a brace list such as
// {dist/a,dist/b}, and a dist/ file given to an option of one of the
// wrappers, which reads as the command that follows the options
// (xargs -a dist/release-assets.txt).
//
// What a static pattern cannot see is left to review: a path whose every part
// comes from a variable, such as "${dir}/${target}/${name}"; a find, or any
// other listing, that picks the binary by anything but its name, as
// -name 'speed*', -perm and -executable do, or by no test at all, before
// something runs what it lists; a top-level dist/ file with any name but the
// binary's that is kept in a variable or an env: value before it runs, or run
// as the argument of a command other than the wrappers above
// (sh -c '"$1" version' _ dist/tool); a wrapper option that takes a separate
// argument (env -u NAME ./dist/tool); a binary extracted from an archive, or
// a top-level dist/ file copied out of it, under another name; in
// .goreleaser.yaml, a hook that keeps {{ .Path }}, or its directory, in its
// env: (BIN={{ .Path }} or PATH={{ dir .Path }}:...) and runs it from there,
// and a sign, SBOM or publisher command handed a binary as its artifact; and
// whatever an action does with its with: inputs.
var signingJobForbidden = regexp.MustCompile(`(?m)` + strings.Join([]string{
	signingJobTools,
	signingJobBuildOutput,
	`(?:^|[;&|{!\x60]|(?:^|[^=])\(|(?:^|[\s;&|({!\x60])` +
		`(?:if|elif|then|else|do|while|until|exec|command|time|nohup|sudo|env|xargs|bash|sh)\s+(?:-\S*\s+)*)\s*` +
		`(?:[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|\$\([^)]*\)|\x60[^\x60]*\x60|[^\s"'(]+)*\s+)*` +
		`(?:(?:` + shellPathPart + `)?(?:/` + shellPathPart + `)*/?dist/|` + goreleaserBuiltBinary + `)`,
	`-(?:exec|ok)(?:dir)?\s+["']?(?:\./)?\{\}`,
	`(?:^|\s)-i?(?:name|path|wholename)\s+["']?(?:[^\s"']*/)?(?i:speedns(?:\.exe)?)["']?(?:$|[\s;|&)])`,
}, "|"))

// signingJobForbiddenValue is signingJobForbidden for an env: value: the tools
// and the paths into the build output only. A variable naming a top-level
// dist/ file is a read as often as not, and only the script that uses it
// would tell.
var signingJobForbiddenValue = regexp.MustCompile(`(?m)` + signingJobTools + `|` + signingJobBuildOutput)

// signingJobDirectory matches a working directory, or a local action, inside
// dist/ or the build output. A script run there can name a built file with
// no dist/ in front of it and no name the pattern knows, as
// for b in */*; do "$b" version; done does, so only the directory tells, and
// a signing job has nothing to run there.
var signingJobDirectory = regexp.MustCompile(`(?m)(?:^|/)dist(?:/|$)|` + signingJobBuildOutput)

// shellCommentLine is a run: script line holding only a comment.
var shellCommentLine = regexp.MustCompile(`(?m)^\s*#.*$`)

// shellContinuation is a backslash that ends a line, and so continues the
// command on the next one: the backslashes before it, if any, come in pairs
// that only escape each other.
var shellContinuation = regexp.MustCompile(`(?m)((?:^|[^\\])(?:\\\\)*)\\\n`)

// shellCode drops a script's comment lines, which may well name a command
// that the script does not run, and then joins each continued line to the
// next, as the shell does, so an argument on a continuation line reads as the
// argument it is, not as a command at the start of a line. The comments go
// first because a backslash at the end of one continues nothing.
func shellCode(script string) string {
	return shellContinuation.ReplaceAllString(shellCommentLine.ReplaceAllString(script, ""), "${1} ")
}

// configStrings collects every string in a parsed YAML document.
func configStrings(node any) []string {
	switch value := node.(type) {
	case string:
		return []string{value}
	case []any:
		var found []string
		for _, item := range value {
			found = append(found, configStrings(item)...)
		}
		return found
	case map[string]any:
		var found []string
		for _, item := range value {
			found = append(found, configStrings(item)...)
		}
		return found
	}
	return nil
}

// readGoReleaserConfig decodes .goreleaser.yaml into document.
func readGoReleaserConfig(t *testing.T, document any) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(content, document); err != nil {
		t.Fatalf(".goreleaser.yaml: %v", err)
	}
}

// TestJobsThatCanSignRunNoTestsOrBuiltBinaries holds every workflow to the
// release.yml split. Any code that runs in a job holding id-token: write can
// request an OIDC token and have Sigstore certify it as that workflow, so a
// test dependency or a built binary run there could sign a bundle that passes
// the identity README.md documents. GitHub scopes permissions per job, not
// per step, so such a job must not run them at all. A job that runs
// GoReleaser runs its hooks and its SBOM and signing commands as well, so
// .goreleaser.yaml is held to the same rule.
func TestJobsThatCanSignRunNoTestsOrBuiltBinaries(t *testing.T) {
	signers := 0
	for _, workflowPath := range workflowPaths(t) {
		found, findings := signingJobFindings(t, filepath.Base(workflowPath), readWorkflow(t, workflowPath))
		signers += found
		for _, finding := range findings {
			t.Error(finding)
		}
	}
	if signers == 0 {
		t.Fatal("no workflow job holds id-token: write; release.yml signs with one, so the structure no longer matches this test")
	}
}

// signingJobFindings returns what each job of the workflow file name that can
// mint OIDC tokens runs, or is pointed at, that such a job must not, and the
// number of those jobs. A step can be pointed at a built binary from outside
// its run: script as well: by an env: value that the script runs, by its
// working directory or its shell, each set on the step, the job or the whole
// workflow, and by a local action. Each of those is read.
func signingJobFindings(t *testing.T, name string, document workflowFile) (signers int, findings []string) {
	t.Helper()
	for jobName, job := range document.Jobs {
		if !grantsWrite(jobPermissions(document, job), "id-token") {
			continue
		}
		signers++
		check := func(where, value string, pattern *regexp.Regexp) {
			if found := pattern.FindString(value); found != "" {
				findings = append(findings, fmt.Sprintf("%s job %s can mint OIDC tokens but %s points at %q; move it to a job without id-token: write",
					name, jobName, where, strings.TrimSpace(found)))
			}
		}
		for key, value := range document.Env {
			check("the workflow's env "+key, fmt.Sprint(value), signingJobForbiddenValue)
		}
		for key, value := range job.Env {
			check("its env "+key, fmt.Sprint(value), signingJobForbiddenValue)
		}
		for level, defaults := range map[string]workflowDefaults{"the workflow's": document.Defaults, "its": job.Defaults} {
			check(level+" default shell", defaults.Run.Shell, signingJobForbidden)
			check(level+" default working-directory", defaults.Run.WorkingDirectory, signingJobDirectory)
		}
		for _, step := range job.Steps {
			if found := signingJobForbidden.FindString(shellCode(step.Run)); found != "" {
				findings = append(findings, fmt.Sprintf("%s job %s can mint OIDC tokens but its step %q runs %q; move it to a job without id-token: write",
					name, jobName, step.Name, strings.TrimSpace(found)))
			}
			for key, value := range step.Env {
				check(fmt.Sprintf("its step %q env %s", step.Name, key), fmt.Sprint(value), signingJobForbiddenValue)
			}
			check(fmt.Sprintf("its step %q shell", step.Name), step.Shell, signingJobForbidden)
			check(fmt.Sprintf("its step %q working-directory", step.Name), step.WorkingDirectory, signingJobDirectory)
			if strings.HasPrefix(step.Uses, "./") {
				check(fmt.Sprintf("the local action its step %q uses", step.Name), step.Uses, signingJobDirectory)
			}
			if !strings.HasPrefix(step.Uses, "goreleaser/goreleaser-action@") {
				continue
			}
			var config any
			readGoReleaserConfig(t, &config)
			for _, command := range configStrings(config) {
				if found := signingJobForbidden.FindString(command); found != "" {
					findings = append(findings, fmt.Sprintf(".goreleaser.yaml runs %q, and %s job %s, which can mint OIDC tokens, runs GoReleaser",
						strings.TrimSpace(found), name, jobName))
				}
			}
		}
	}
	return signers, findings
}

// signingWorkflow is a workflow with one job, which can sign, and one step in
// it. The YAML lines in workflow, job and step are added at those levels.
func signingWorkflow(workflow, job, step string) string {
	indent := func(text, prefix string) string {
		if text == "" {
			return ""
		}
		return prefix + strings.ReplaceAll(strings.TrimSuffix(text, "\n"), "\n", "\n"+prefix) + "\n"
	}
	return "permissions:\n  contents: read\n" + indent(workflow, "") +
		"jobs:\n  publish:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n" + indent(job, "    ") +
		"    steps:\n      - name: Smoke\n" + indent(step, "        ")
}

// TestSigningJobFindingsReadMoreThanScripts pins what signingJobFindings reads
// besides a run: script. The checks of the second review's fixes pointed a
// publish step at a build directory five ways that no script names: through
// an env: value set on the step, on the job or under the workspace, and
// through working-directory:, in dist/ itself or in a build directory. A
// shell: or a local action can do the same. The publish job's own env: values
// must keep passing.
func TestSigningJobFindingsReadMoreThanScripts(t *testing.T) {
	cases := []struct {
		name                string
		workflow, job, step string
		forbidden           bool
	}{
		{name: "build directory in a step's env", step: "env:\n  SPEEDNS_BIN: dist/speedns_linux_amd64_v1/speedns\nrun: '\"${SPEEDNS_BIN}\" version'", forbidden: true},
		{name: "build directory under the workspace in a step's env", step: "env:\n  SPEEDNS_BIN: ${{ github.workspace }}/dist/speedns_linux_amd64_v1/speedns\nrun: '\"${SPEEDNS_BIN}\" version'", forbidden: true},
		{name: "build directory in the job's env", job: "env:\n  SPEEDNS_BIN: dist/speedns_linux_amd64_v1/speedns", step: "run: '\"${SPEEDNS_BIN}\" version'", forbidden: true},
		{name: "build directory in the workflow's env", workflow: "env:\n  SPEEDNS_BIN: dist/speedns_linux_amd64_v1/speedns", step: "run: '\"${SPEEDNS_BIN}\" version'", forbidden: true},
		{name: "top-level binary in a step's env", step: "env:\n  SPEEDNS_BIN: dist/speedns\nrun: '\"${SPEEDNS_BIN}\" version'", forbidden: true},
		{name: "test command in a step's env", step: "env:\n  CHECK: go test ./...\nrun: ${CHECK}", forbidden: true},
		{name: "working directory in a build directory", step: "working-directory: dist/speedns_linux_amd64_v1\nrun: ./speedns version", forbidden: true},
		{name: "working directory in dist", step: "working-directory: dist\nrun: for b in */speedns; do \"$b\" version; done", forbidden: true},
		{name: "working directory in dist, no name in the script", step: "working-directory: dist\nrun: for b in */*; do \"$b\" version; done", forbidden: true},
		{name: "working directory in dist under the workspace", step: "working-directory: ${{ github.workspace }}/dist\nrun: ./tool version", forbidden: true},
		{name: "job default working directory", job: "defaults:\n  run:\n    working-directory: dist", step: "run: ./tool version", forbidden: true},
		{name: "workflow default working directory", workflow: "defaults:\n  run:\n    working-directory: ./dist", step: "run: ./tool version", forbidden: true},
		{name: "shell from dist", step: "shell: ./dist/tool {0}\nrun: version", forbidden: true},
		{name: "job default shell from a build directory", job: "defaults:\n  run:\n    shell: dist/speedns_linux_amd64_v1/speedns {0}", step: "run: version", forbidden: true},
		{name: "workflow default shell from dist", workflow: "defaults:\n  run:\n    shell: dist/tool {0}", step: "run: version", forbidden: true},
		{name: "local action in dist", step: "uses: ./dist/action", forbidden: true},

		{name: "the publish job's env", workflow: "env:\n  GO_VERSION: '1.26.x'\n  RELEASE_TAG: ${{ inputs.tag || github.ref_name }}\n  GORELEASER_CURRENT_TAG: ${{ inputs.tag || github.ref_name }}",
			step: "env:\n  VERIFIED_COMMIT: ${{ needs.verify.outputs.commit }}\n  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n  COSIGN_YES: 'true'\n  GORELEASER_PREVIOUS_TAG: ${{ needs.verify.outputs.previous-tag }}\nrun: git rev-parse HEAD"},
		{name: "top-level file to read in env", step: "env:\n  CHECKSUMS: dist/checksums.txt\nrun: sha256sum \"${CHECKSUMS}\""},
		{name: "reference as the working directory", step: "working-directory: ${{ runner.temp }}/speedns-repro-reference\nrun: sha256sum --check checksums.txt"},
		{name: "bash as the shell", step: "shell: bash\nrun: bash scripts/release-assets.sh verify dist dist/release-assets.txt"},
		{name: "defaults at the repository root", job: "defaults:\n  run:\n    shell: bash\n    working-directory: .", step: "run: git rev-parse HEAD"},
		{name: "local action elsewhere", step: "uses: ./.github/actions/setup"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := signingWorkflow(tc.workflow, tc.job, tc.step)
			var document workflowFile
			if err := yaml.Unmarshal([]byte(text), &document); err != nil {
				t.Fatalf("the case's workflow does not parse: %v\n%s", err, text)
			}
			signers, findings := signingJobFindings(t, "case.yml", document)
			if signers != 1 {
				t.Fatalf("signingJobFindings counts %d jobs that can sign in a workflow with one:\n%s", signers, text)
			}
			if tc.forbidden && len(findings) == 0 {
				t.Fatalf("signingJobFindings lets a job that can sign be pointed at what it must not run by:\n%s", text)
			}
			if !tc.forbidden && len(findings) > 0 {
				t.Fatalf("signingJobFindings refuses a job that runs nothing it built:\n%s\n%s", strings.Join(findings, "\n"), text)
			}
		})
	}
}

// TestSigningJobPatternTellsRunsFromReads pins what signingJobForbidden
// catches. TestJobsThatCanSignRunNoTestsOrBuiltBinaries sees only the
// workflows and .goreleaser.yaml as they stand, and each review of the release
// split ran something the pattern let through: a binary still inside dist/
// five ways in the second review; more forms in the checks of that fix, among
// them quoted assignments, ../../, absolute paths, expressions and
// find -exec ./{}; and in the checks after those, a binary that find picks by
// its name and a GoReleaser build hook that runs {{ .Path }}. Each is a case
// here. signingJobFindings holds every string of .goreleaser.yaml to the
// pattern as well, so such strings are cases too. The publish job's own reads
// of dist/ must keep passing, on one line or continued over several, since
// they are how it compares, uploads and attests the release, and so must the
// config's own strings. The reads the pattern cannot tell from runs are
// pinned as refused, as its comment says.
func TestSigningJobPatternTellsRunsFromReads(t *testing.T) {
	cases := []struct {
		name      string
		script    string
		forbidden bool
	}{
		{name: "go test", script: "go test -count=1 ./...", forbidden: true},
		{name: "go run", script: "go run ./cmd/speedns version", forbidden: true},
		{name: "go generate", script: "go generate ./...", forbidden: true},
		{name: "go tool", script: "go tool cover -func=coverage.out", forbidden: true},
		{name: "coverage gate", script: "bash scripts/coverage.sh", forbidden: true},
		{name: "artifact smoke", script: "bash scripts/artifact-smoke.sh linux dist", forbidden: true},
		{name: "release fixture", script: "bash scripts/release-fixture.sh", forbidden: true},

		{name: "build directory binary", script: "dist/speedns_linux_amd64_v1/speedns version", forbidden: true},
		{name: "dot-slash build directory binary", script: "./dist/speedns_linux_amd64_v1/speedns version", forbidden: true},
		{name: "build directory under the workspace variable", script: `"${GITHUB_WORKSPACE}/dist/speedns_linux_amd64_v1/speedns" version`, forbidden: true},
		{name: "build directory under a pwd substitution", script: `"$(pwd)/dist/speedns_linux_amd64_v1/speedns" version`, forbidden: true},
		{name: "cd into dist", script: "cd dist && ./speedns_linux_amd64_v1/speedns version", forbidden: true},
		{name: "build directory binary in a variable", script: `bin=dist/speedns_linux_amd64_v1/speedns; "${bin}" version`, forbidden: true},
		{name: "cd into a build directory", script: "cd dist/speedns_linux_amd64_v1 && ./speedns version", forbidden: true},
		{name: "build directory with an interpolated arch", script: `"dist/speedns_linux_${arch}_v1/speedns" version`, forbidden: true},
		{name: "glob over build directories", script: `for binary in dist/*/speedns; do "${binary}" version; done`, forbidden: true},
		{name: "glob run inside dist", script: `cd dist; for b in */speedns; do "$b" version; done`, forbidden: true},
		{name: "binary path assembled from parts", script: `"${dir}/${target}/speedns" version`, forbidden: true},
		{name: "binary behind a bare variable", script: `"$dir/speedns" version`, forbidden: true},
		{name: "top-level binary in a variable", script: `bin=dist/speedns; "${bin}" version`, forbidden: true},
		{name: "binary in the current directory", script: "./speedns version", forbidden: true},
		{name: "windows binary", script: `"${dir}/speedns.exe" version`, forbidden: true},

		{name: "find exec", script: `find dist -name speedns -type f -exec {} version \;`, forbidden: true},
		{name: "find execdir", script: `find dist -name speedns -type f -execdir "{}" version \;`, forbidden: true},
		{name: "find exec dot-slash", script: `find dist -name speedns -type f -exec ./{} version \;`, forbidden: true},
		{name: "find okdir", script: `find dist -type f -okdir {} version \;`, forbidden: true},
		// find picks the binary by its name, and something else runs it.
		{name: "found binary kept in a variable", script: "bin=\"$(find dist -type f -name speedns | head -n1)\"\n\"${bin}\" version", forbidden: true},
		{name: "found binary run by xargs", script: `find dist -name speedns | xargs -I{} {} version`, forbidden: true},
		{name: "found binary by iname", script: `bin="$(find dist -iname speedns -print -quit)"; "$bin" version`, forbidden: true},
		{name: "found binary run by sh -c", script: `find dist -type f -name speedns -exec sh -c '"$1" version' _ {} \;`, forbidden: true},
		{name: "found binary run by env", script: `find dist -type f -name speedns -exec env {} version \;`, forbidden: true},
		{name: "found binary in the project's spelling", script: `find dist -iname SpeeDNS -print`, forbidden: true},
		{name: "found binary by a path in any case", script: `find dist -ipath "*/SpeeDNS" -print`, forbidden: true},
		{name: "found windows binary", script: `find dist -name "speedns.exe" -print`, forbidden: true},

		// Strings of .goreleaser.yaml, which a job that signs runs as
		// GoReleaser's hooks. In a build hook, {{ .Path }} is the binary the
		// build has just made and {{ .Name }} its file name.
		{name: "hook running the built binary", script: "{{ .Path }} version", forbidden: true},
		{name: "hook running the built binary, unspaced", script: "{{.Path}} version", forbidden: true},
		{name: "hook running the quoted built binary", script: `"{{ .Path }}" version`, forbidden: true},
		{name: "hook running the built binary behind a test", script: `sh -c 'test "{{ .Os }}" != linux || {{ .Path }} version'`, forbidden: true},
		{name: "hook running the built binary through bash", script: `bash -c '{{ .Path }} --help'`, forbidden: true},
		{name: "hook running the built binary through env", script: "env {{ .Path }} version", forbidden: true},
		{name: "hook directory of the built binary", script: "{{ dir .Path }}", forbidden: true},
		{name: "hook running the built binary by its name", script: `sh -c 'cd "$(dirname "{{ .Path }}")" && ./{{ .Name }} version'`, forbidden: true},
		{name: "hook path under a template", script: "{{ .Env.GITHUB_WORKSPACE }}/dist/tool version", forbidden: true},

		// A top-level dist/ file run from there. It is called tool, not
		// speedns, so that only the rule for a dist/ path where a command
		// starts can catch it.
		{name: "top-level file", script: "dist/tool version", forbidden: true},
		{name: "dot-slash", script: "./dist/tool version", forbidden: true},
		{name: "parent directory", script: "../dist/tool version", forbidden: true},
		{name: "two parent directories", script: "../../dist/tool version", forbidden: true},
		{name: "home directory", script: "~/work/SpeeDNS/dist/tool version", forbidden: true},
		{name: "absolute path", script: "/srv/work/SpeeDNS/dist/tool version", forbidden: true},
		{name: "workspace variable", script: `"${GITHUB_WORKSPACE}/dist/tool" version`, forbidden: true},
		{name: "workspace expression", script: `"${{ github.workspace }}/dist/tool" version`, forbidden: true},
		{name: "pwd substitution", script: `"$(pwd)/dist/tool" version`, forbidden: true},
		{name: "variable quoted apart", script: `"${GITHUB_WORKSPACE}"/dist/tool version`, forbidden: true},
		{name: "bare variable", script: "$PWD/dist/tool version", forbidden: true},
		{name: "variables then dist", script: `"${HOME}/${repository}/dist/tool" version`, forbidden: true},
		{name: "after and", script: "test -x dist/tool && dist/tool version", forbidden: true},
		{name: "if condition", script: "if dist/tool version; then echo ran; fi", forbidden: true},
		{name: "negated", script: "! ./dist/tool version", forbidden: true},
		{name: "assignment prefix", script: "SPEEDNS_DEBUG=1 ./dist/tool version", forbidden: true},
		{name: "quoted assignment prefix", script: `SPEEDNS_LABEL="smoke run" ./dist/tool version`, forbidden: true},
		{name: "single-quoted assignment prefix", script: `SPEEDNS_LABEL='smoke run' ./dist/tool version`, forbidden: true},
		{name: "substitution in an assignment prefix", script: "SPEEDNS_DATE=$(date -u +%F) ./dist/tool version", forbidden: true},
		{name: "sudo", script: "sudo ./dist/tool version", forbidden: true},
		{name: "sudo with options", script: "sudo -E ./dist/tool version", forbidden: true},
		{name: "env with an assignment", script: "env SPEEDNS_DEBUG=1 ./dist/tool version", forbidden: true},
		{name: "env with options", script: "env -i ./dist/tool version", forbidden: true},
		{name: "xargs", script: `printf '%s\n' --help | xargs -n1 ./dist/tool`, forbidden: true},
		{name: "shell command string", script: `bash -c './dist/tool version'`, forbidden: true},
		{name: "command substitution", script: `version="$(dist/tool version)"`, forbidden: true},
		{name: "backticks", script: "version=\x60dist/tool version\x60", forbidden: true},
		{name: "brace group", script: "{ dist/tool version; }", forbidden: true},
		{name: "subshell", script: "(dist/tool version)", forbidden: true},
		{name: "loop body", script: "for target in a b; do\n  dist/tool version\ndone", forbidden: true},
		{name: "continued assignment prefix", script: "SPEEDNS_DEBUG=1 \\\n  ./dist/tool version", forbidden: true},
		{name: "continued wrapper", script: "env \\\n  ./dist/tool version", forbidden: true},
		{name: "line after an escaped backslash", script: "echo done \\\\\n./dist/tool version", forbidden: true},
		{name: "line after a continued comment", script: "# no longer run here \\\n./dist/tool version", forbidden: true},

		// Reads the pattern cannot tell from runs, refused as its comment says.
		{name: "array written one item per line", script: "assets=(\n  dist/checksums.txt\n)", forbidden: true},
		{name: "here-document listing", script: "cat >assets.txt <<'EOF'\ndist/checksums.txt\nEOF", forbidden: true},
		{name: "brace list", script: "sha256sum {dist/checksums.txt,dist/CHANGELOG.md}", forbidden: true},
		{name: "hash of a build directory binary", script: "sha256sum dist/speedns_linux_amd64_v1/speedns", forbidden: true},
		{name: "hash of a binary found by its name", script: "find dist -name speedns -exec sha256sum {} +", forbidden: true},
		{name: "wrapper option naming a dist/ file", script: `xargs -a dist/release-assets.txt gh release upload "${RELEASE_TAG}"`, forbidden: true},

		{name: "reproducibility comparison", script: `bash scripts/compare-release-artifacts.sh "${RUNNER_TEMP}/speedns-repro-reference" dist`},
		{name: "asset list check", script: "bash scripts/release-assets.sh verify dist dist/release-assets.txt"},
		{name: "asset list read", script: "mapfile -t release_assets <dist/release-assets.txt"},
		{name: "upload", script: `gh release upload "${RELEASE_TAG}" --clobber dist/checksums.txt dist/SpeeDNS_0.7.0_linux_amd64.tar.gz dist/speedns_0.7.0_linux_amd64.deb`},
		{name: "upload a prerelease package", script: `gh release upload "${RELEASE_TAG}" dist/speedns_1.0.0-rc.1_linux_arm64.rpm`},
		{name: "upload on continuation lines", script: "gh release upload \"${RELEASE_TAG}\" \\\n  --clobber \\\n  dist/checksums.txt \\\n  dist/*.tar.gz"},
		{name: "hash with a glob", script: "sha256sum dist/*.tar.gz dist/*.deb dist/*.sbom.json"},
		{name: "loop over the archives", script: `for archive in dist/*.tar.gz; do sha256sum "${archive}"; done`},
		{name: "hash on continuation lines", script: "sha256sum \\\n  dist/checksums.txt \\\n  dist/*.tar.gz"},
		{name: "hash through the workspace", script: `sha256sum "${GITHUB_WORKSPACE}/dist/checksums.txt"`},
		{name: "hash through the workspace quoted apart", script: `sha256sum "${GITHUB_WORKSPACE}"/dist/checksums.txt`},
		{name: "hash with a quoted assignment prefix", script: `LC_ALL="C.UTF-8" sha256sum dist/checksums.txt`},
		{name: "array on one line", script: `assets=(dist/*.tar.gz dist/checksums.txt); sha256sum "${assets[@]}"`},
		{name: "appended array", script: "assets+=(dist/checksums.txt)"},
		{name: "listing in a substitution", script: `files="$(ls dist/*.sbom.json)"`},
		{name: "check in a subshell", script: "(cd dist && sha256sum --check checksums.txt)"},
		{name: "find hashing", script: `find dist -maxdepth 1 -name '*.sbom.json' -exec sha256sum {} +`},
		{name: "find hashing the packages", script: `find dist -maxdepth 1 -name 'speedns_*.deb' -exec sha256sum {} +`},
		{name: "SBOM with a source name", script: "syft scan dist/SpeeDNS_0.7.0_linux_amd64.tar.gz --source-name speedns --output spdx-json=sbom.json"},
		{name: "compare with the reference", script: `cmp dist/checksums.txt "${RUNNER_TEMP}/speedns-repro-reference/checksums.txt"`},
		{name: "reference directory", script: `ls "${RUNNER_TEMP}/speedns-repro-reference"`},
		{name: "changelog", script: "if [[ -f dist/CHANGELOG.md ]]; then\n  bash scripts/ensure-release.sh \"${RELEASE_TAG}\" dist/CHANGELOG.md\nfi"},
		{name: "changelog in a variable", script: `changelog=dist/CHANGELOG.md; test -s "${changelog}"`},
		{name: "missing changelog", script: "if [[ ! -f dist/CHANGELOG.md ]]; then echo none; fi"},
		{name: "cask beside the binary's name", script: "test -s dist/speedns.rb"},
		{name: "the binary's Go package", script: "go list ./cmd/speedns"},
		{name: "signature check", script: "cosign verify-blob --bundle dist/checksums.txt.sigstore.json dist/checksums.txt"},
		{name: "artifact metadata", script: "jq -r '.[].path' dist/artifacts.json"},
		{name: "log redirection", script: ": >dist/release-smoke.log"},
		{name: "log through tee", script: "{\n  bash scripts/release-assets.sh verify dist dist/release-assets.txt\n} 2>&1 | tee dist/release-smoke.log"},
		{name: "go version", script: "go version"},
		{name: "module cache", script: "go env GOMODCACHE"},

		{name: "hook given the built binary", script: "./scripts/normalize-build-mtime.sh {{ .Path }}"},
		{name: "archive name template", script: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"},
		{name: "SBOM document name", script: "{{ .ArtifactName }}.sbom.json"},
		{name: "commit timestamp", script: "{{ .CommitTimestamp }}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := signingJobForbidden.FindString(shellCode(tc.script))
			if tc.forbidden && found == "" {
				t.Fatalf("signingJobForbidden lets a job that can sign run:\n%s", tc.script)
			}
			if !tc.forbidden && found != "" {
				t.Fatalf("signingJobForbidden refuses %q in a script that runs nothing it built:\n%s", strings.TrimSpace(found), tc.script)
			}
		})
	}
}

// neededOutput is an expression reading another job's output, and stepOutput
// a job output mapped from one of the job's steps.
var (
	neededOutput = regexp.MustCompile(`^\$\{\{\s*needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}$`)
	stepOutput   = regexp.MustCompile(`^\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}$`)
)

// outputSource follows expression, a needs.<source>.outputs.<name> read in
// the job reader, to the step of source that sets the value. It returns that
// step's index and the name of the step output it is mapped from, or ok false
// when the expression reads anything else or the chain breaks on the way.
func outputSource(document workflowFile, reader workflowJob, expression, source string) (index int, output string, ok bool) {
	match := neededOutput.FindStringSubmatch(strings.TrimSpace(expression))
	if match == nil || match[1] != source || !slices.Contains(jobNeeds(reader), source) {
		return 0, "", false
	}
	mapped := stepOutput.FindStringSubmatch(strings.TrimSpace(document.Jobs[source].Outputs[match[2]]))
	if mapped == nil {
		return 0, "", false
	}
	for position, step := range document.Jobs[source].Steps {
		if step.ID == mapped[1] {
			return position, mapped[2], true
		}
	}
	return 0, "", false
}

// stepIndex returns the first step of job that satisfies matches, or -1.
func stepIndex(job workflowJob, matches func(workflowStep) bool) int {
	for index, step := range job.Steps {
		if matches(step) {
			return index
		}
	}
	return -1
}

// releaseGates are the checks a release must still pass after the split, in a
// job that cannot sign: dropping one from the verify job must not go unseen
// just because the publish job is no longer allowed to run it.
var releaseGates = []string{
	"go mod verify",
	"gofmt -l",
	"go test -count=1 ./...",
	"go test -count=1 -race ./...",
	"go vet ./...",
	"scripts/coverage.sh",
	"scripts/release-fixture.sh",
	"scripts/release-assets.sh verify",
	"scripts/artifact-smoke.sh linux",
	"scripts/artifact-smoke.sh macos-archives",
}

// githubHostedUbuntu is a standard GitHub-hosted Ubuntu runner label, such as
// ubuntu-latest, ubuntu-24.04 or ubuntu-24.04-arm.
var githubHostedUbuntu = regexp.MustCompile(`^ubuntu-(?:latest|[0-9]+\.[0-9]+(?:-arm)?)$`)

// runnerLabels reads runs-on: as the labels a runner must carry, all of them.
// A runner group, or any other form, yields none.
func runnerLabels(runsOn any) []string {
	switch value := runsOn.(type) {
	case string:
		return []string{value}
	case []any:
		labels := make([]string, 0, len(value))
		for _, label := range value {
			labels = append(labels, fmt.Sprint(label))
		}
		return labels
	}
	return nil
}

// TestReleaseWorkflowVerifiesOnAnotherRunnerBeforeItSigns pins how the two
// release jobs fit together. The workflow-level token is read-only, and one
// job, behind the protected environment, can sign. Every gate runs in a
// read-only job, and the signing job needs one that builds the
// reproducibility reference, so the signed build is compared with a build
// from another runner with a cold cache, not with one that shared its
// machine. Both jobs run on GitHub-hosted runners, which give each job a
// fresh machine. The comparison comes before anything is uploaded. Before it
// builds, the signing job checks that it has the commit the verify job
// tested, recorded before any of the tag's code ran, and it builds with the
// Go release the reference was built with: GO_VERSION is a range that two
// runners can resolve differently, which would fail the comparison on the
// toolchain alone.
func TestReleaseWorkflowVerifiesOnAnotherRunnerBeforeItSigns(t *testing.T) {
	release := releaseWorkflow(t)
	if release.Permissions == nil || grantsWrite(release.Permissions, "") {
		t.Errorf("release.yml grants %v to every job; keep the workflow-level permissions read-only", release.Permissions)
	}

	var signerName string
	for jobName, job := range release.Jobs {
		if grantsWrite(jobPermissions(release, job), "id-token") {
			if signerName != "" {
				t.Fatalf("release.yml jobs %s and %s can both mint OIDC tokens; only the publish job should", signerName, jobName)
			}
			signerName = jobName
		}
	}
	if signerName == "" {
		t.Fatal("no release.yml job holds id-token: write, so nothing can sign or attest the release")
	}
	signer := release.Jobs[signerName]
	if environmentName(signer.Environment) != "release" {
		t.Errorf("release.yml job %s signs outside the protected release environment", signerName)
	}

	isGoReleaser := func(step workflowStep) bool {
		return strings.HasPrefix(step.Uses, "goreleaser/goreleaser-action@")
	}
	isReference := func(step workflowStep) bool {
		arguments := withValue(step, "args")
		return isGoReleaser(step) && strings.Contains(arguments, "--skip=sign") && !strings.Contains(arguments, "--snapshot")
	}
	var verifierName string
	for _, needed := range jobNeeds(signer) {
		job, ok := release.Jobs[needed]
		if !ok {
			t.Fatalf("release.yml job %s needs %s, which does not exist", signerName, needed)
		}
		if grantsWrite(jobPermissions(release, job), "") {
			t.Errorf("release.yml job %s, which %s needs, holds write permissions; the verification job must be read-only", needed, signerName)
		}
		if stepIndex(job, isReference) >= 0 {
			verifierName = needed
		}
	}
	if verifierName == "" {
		t.Fatalf("release.yml job %s needs no read-only job that builds the unsigned reproducibility reference", signerName)
	}
	verifier := release.Jobs[verifierName]
	// Behind an environment, the gates would wait for the same approval as
	// the signing, and could read the environment's secrets while they ran.
	if name := environmentName(verifier.Environment); name != "" {
		t.Errorf("release.yml job %s runs in the %s environment; the verification job must need no approval and see no environment secrets", verifierName, name)
	}
	if stepIndex(signer, isReference) >= 0 {
		t.Errorf("release.yml job %s builds the reproducibility reference itself; it must come from %s, on another runner", signerName, verifierName)
	}

	// A self-hosted runner can keep a build cache, a toolchain or a planted
	// file from one job to the next, so the reference would no longer come
	// from a fresh machine, and README.md's gh attestation verify
	// --deny-self-hosted-runners would refuse every artifact, but only after
	// the release was published. Every label must match: a runner has to
	// carry all of them, so [self-hosted, ubuntu-latest] picks a self-hosted
	// one.
	for _, jobName := range []string{verifierName, signerName} {
		runsOn := release.Jobs[jobName].RunsOn
		labels := runnerLabels(runsOn)
		hosted := len(labels) > 0
		for _, label := range labels {
			hosted = hosted && githubHostedUbuntu.MatchString(label)
		}
		if !hosted {
			t.Errorf("release.yml job %s runs on %v; both release jobs need a GitHub-hosted ubuntu-* runner, a fresh machine for each job", jobName, runsOn)
		}
	}

	readOnly := ""
	for _, job := range release.Jobs {
		if !grantsWrite(jobPermissions(release, job), "") {
			for _, step := range job.Steps {
				readOnly += shellCode(step.Run) + "\n"
			}
		}
	}
	for _, gate := range releaseGates {
		if !strings.Contains(readOnly, gate) {
			t.Errorf("release.yml no longer runs %q in a read-only job", gate)
		}
	}

	// The reference reaches the signing job only as an artifact.
	uploaded := map[string]bool{}
	for _, step := range verifier.Steps {
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			uploaded[withValue(step, "name")] = true
		}
	}
	downloaded := stepIndex(signer, func(step workflowStep) bool {
		return strings.HasPrefix(step.Uses, "actions/download-artifact@") && uploaded[withValue(step, "name")]
	})
	signed := stepIndex(signer, func(step workflowStep) bool {
		return isGoReleaser(step) && !strings.Contains(withValue(step, "args"), "--skip=sign")
	})
	compared := stepIndex(signer, func(step workflowStep) bool {
		return strings.Contains(step.Run, "scripts/compare-release-artifacts.sh")
	})
	published := stepIndex(signer, func(step workflowStep) bool {
		return strings.Contains(step.Run, "gh release upload") || strings.Contains(step.Run, "scripts/ensure-release.sh") ||
			strings.HasPrefix(step.Uses, "actions/attest@")
	})
	if downloaded < 0 || signed < 0 || compared < 0 || published < 0 ||
		downloaded >= compared || signed >= compared || compared >= published {
		t.Errorf("release.yml job %s must download the reference %s uploaded and build the signed artifacts, then compare them, "+
			"before it creates, uploads or attests anything; got steps %d, %d, %d, %d", signerName, verifierName, downloaded, signed, compared, published)
	}

	// Built with the Go release the reference used.
	goSetups := 0
	for _, step := range signer.Steps {
		if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
			continue
		}
		goSetups++
		index, output, ok := outputSource(release, signer, withValue(step, "go-version"), verifierName)
		if !ok || output != "go-version" || !strings.HasPrefix(verifier.Steps[index].Uses, "actions/setup-go@") {
			t.Errorf("release.yml job %s sets up Go %s, not the version %s's setup-go resolved; a different patch release cannot reproduce the reference",
				signerName, withValue(step, "go-version"), verifierName)
		}
	}
	if goSetups == 0 {
		t.Errorf("release.yml job %s does not set up Go; update this test if Go is installed another way", signerName)
	}

	// Built from the commit the verify job tested, and checked before the
	// signing build. A check that merely exists is not enough: placed after
	// the build, it lets a tag moved during the wait for approval be built
	// and signed before it stops the job, and placed after the uploads,
	// published and attested as well.
	confirmedAt := -1
	for index, step := range signer.Steps {
		for _, value := range step.Env {
			recorded, _, ok := outputSource(release, signer, fmt.Sprint(value), verifierName)
			if !ok || !strings.Contains(verifier.Steps[recorded].Run, "git rev-parse HEAD") || !strings.Contains(step.Run, "git rev-parse HEAD") {
				continue
			}
			if confirmedAt < 0 {
				confirmedAt = index
			}
			setup := stepIndex(verifier, func(step workflowStep) bool { return strings.HasPrefix(step.Uses, "actions/setup-go@") })
			if setup >= 0 && recorded > setup {
				t.Errorf("release.yml job %s records the verified commit after setting up Go; record it before any of the tag's code runs", verifierName)
			}
		}
	}
	switch {
	case confirmedAt < 0:
		t.Errorf("release.yml job %s does not check that it builds the commit %s recorded and tested", signerName, verifierName)
	case signed >= 0 && confirmedAt > signed:
		t.Errorf("release.yml job %s checks that the tag still names the commit %s tested only at step %d, after the signing build at step %d; "+
			"check it before anything is built or signed", signerName, verifierName, confirmedAt, signed)
	}
}

// gitPush matches a git invocation that pushes.
var gitPush = regexp.MustCompile(`\bgit\b[^\n]*\spush\b`)

// selfCheckouts are actions that run actions/checkout themselves, with its
// default of persisting the token, unless the named input turns that off.
// A workflow using one checks out in a step of its own instead.
var selfCheckouts = map[string]struct{ input, value string }{
	// Its checkout step runs unless repo-checkout is exactly 'false'.
	"golang/govulncheck-action": {input: "repo-checkout", value: "false"},
}

// TestWorkflowCheckoutsDoNotPersistCredentials keeps the checkout token out of
// .git/config, in every workflow file, so a new workflow is held to it too.
// By default actions/checkout leaves it there for every later step, including
// the tests, the built binaries and any compromised action, to read, and an
// upload that includes the checkout's .git directory takes it along. Where a
// workflow can write the repository, so can that token; elsewhere it still
// reads the repository and, in CodeQL's case, writes security events. The
// one step that pushes must therefore bring its own token.
func TestWorkflowCheckoutsDoNotPersistCredentials(t *testing.T) {
	checkouts := 0
	for _, workflowPath := range workflowPaths(t) {
		name := filepath.Base(workflowPath)
		for jobName, job := range readWorkflow(t, workflowPath).Jobs {
			for _, step := range job.Steps {
				if strings.HasPrefix(step.Uses, "actions/checkout@") {
					checkouts++
					if persist := withValue(step, "persist-credentials"); persist != "false" {
						t.Errorf("%s job %s checks out with persist-credentials %s, want false", name, jobName, persist)
					}
				}
				for action, off := range selfCheckouts {
					if strings.HasPrefix(step.Uses, action+"@") && withValue(step, off.input) != off.value {
						t.Errorf("%s job %s runs %s, which checks out and persists the token itself unless %s is %s; check out in a step of its own instead",
							name, jobName, action, off.input, off.value)
					}
				}
				if !gitPush.MatchString(shellCode(step.Run)) {
					continue
				}
				token := false
				for _, value := range step.Env {
					token = token || strings.Contains(fmt.Sprint(value), "secrets.GITHUB_TOKEN")
				}
				if !token {
					t.Errorf("%s job %s step %q pushes without a token in the step's env; the checkout no longer persists one", name, jobName, step.Name)
				}
			}
		}
	}
	if checkouts == 0 {
		t.Fatal("no actions/checkout steps found; the workflow structure no longer matches this test")
	}
}

// goreleaserConfig holds only the parts of .goreleaser.yaml the tests below
// read.
type goreleaserConfig struct {
	NFPMs []struct {
		ID      string   `yaml:"id"`
		Formats []string `yaml:"formats"`
		RPM     struct {
			BuildHost string `yaml:"buildhost"`
		} `yaml:"rpm"`
	} `yaml:"nfpms"`
	SBOMs []struct {
		ID   string   `yaml:"id"`
		Cmd  string   `yaml:"cmd"`
		Args []string `yaml:"args"`
		Env  []string `yaml:"env"`
	} `yaml:"sboms"`
}

// smokeBuildHost is the build host scripts/artifact-smoke.sh expects every RPM
// header to record.
var smokeBuildHost = regexp.MustCompile(`(?m)^expected_rpm_buildhost=(\S+)$`)

// TestReleaseRPMsRecordAFixedBuildHost keeps the build machine out of the
// RPMs. nfpm writes os.Hostname() into every RPM header unless rpm.buildhost
// is set, and the release builds its reference and its signed artifacts on
// two runners, with two host names. Every RPM, its SBOM and checksums.txt
// would then differ between the builds, compare-release-artifacts.sh would
// stop every release, and nothing would be signed. A template is refused as
// well, since one only exists to vary with the build. The value is the one
// artifact-smoke.sh checks the built headers against, so the CI snapshot and
// the release's verify job both prove the setting takes effect.
func TestReleaseRPMsRecordAFixedBuildHost(t *testing.T) {
	var config goreleaserConfig
	readGoReleaserConfig(t, &config)
	content, err := os.ReadFile(filepath.Join("..", "scripts", "artifact-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	smoke := smokeBuildHost.FindStringSubmatch(string(content))
	if smoke == nil || !strings.Contains(string(content), "%{BUILDHOST}") {
		t.Fatal("scripts/artifact-smoke.sh no longer checks the RPM BUILDHOST header against expected_rpm_buildhost; update this test")
	}

	rpms := 0
	for _, entry := range config.NFPMs {
		if !slices.Contains(entry.Formats, "rpm") {
			continue
		}
		rpms++
		host := entry.RPM.BuildHost
		switch {
		case strings.TrimSpace(host) == "":
			t.Errorf(".goreleaser.yaml nfpms entry %s builds RPMs without rpm.buildhost, so each records its runner's host name", entry.ID)
		case strings.Contains(host, "{{"):
			t.Errorf(".goreleaser.yaml nfpms entry %s sets rpm.buildhost to the template %q; use a fixed literal", entry.ID, host)
		case host != smoke[1]:
			t.Errorf(".goreleaser.yaml nfpms entry %s records build host %q, but scripts/artifact-smoke.sh expects %q", entry.ID, host, smoke[1])
		}
	}
	if rpms == 0 {
		t.Fatal("no .goreleaser.yaml nfpms entry builds RPMs; update this test and scripts/artifact-smoke.sh")
	}
}

// syftConfigOption is an argument that names a Syft configuration file:
// --config, or its short form -c, alone or at the end of a cluster of the
// short flags that take no value, -h, -q and -v. Syft's flag parser,
// spf13/pflag, reads a cluster one letter at a time until a letter whose flag
// takes a value, so -qc planted.yaml and -vcplanted.yaml both name
// planted.yaml, while in -oc the c is the value of -o. It is written so that
// bash reads it alike, as scripts/reproducible-syft.sh's config_option.
var syftConfigOption = regexp.MustCompile(`^(--config|-[hqv]*c)`)

// wrapperConfigOption is where scripts/reproducible-syft.sh sets the
// expression it refuses configuration options with.
var wrapperConfigOption = regexp.MustCompile(`(?m)^config_option='([^']*)'$`)

// TestSyftConfigOptionMatchesEveryForm pins syftConfigOption, and that
// scripts/reproducible-syft.sh refuses the same arguments. The checks of the
// second review's fixes passed -qc planted.yaml to the SBOM command, which
// both places let through: each refused only arguments that begin with -c.
func TestSyftConfigOptionMatchesEveryForm(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "scripts", "reproducible-syft.sh"))
	if err != nil {
		t.Fatal(err)
	}
	wrapper := ""
	if match := wrapperConfigOption.FindStringSubmatch(string(content)); match != nil {
		wrapper = match[1]
	}
	if wrapper != syftConfigOption.String() {
		t.Errorf("scripts/reproducible-syft.sh sets config_option to %q, not %q; the wrapper and this test must refuse the same arguments", wrapper, syftConfigOption)
	}
	for _, argument := range []string{"--config", "--config=planted.yaml", "-c", "-cplanted.yaml", "-c=planted.yaml", "-qc", "-vcplanted.yaml", "-hvqc"} {
		if !syftConfigOption.MatchString(argument) {
			t.Errorf("syftConfigOption lets %q name a second Syft configuration file", argument)
		}
	}
	for _, argument := range []string{"$artifact", "--output", "spdx-json=$document", "-o", "-q", "-vv", "-oc", "--enrich=none"} {
		if syftConfigOption.MatchString(argument) {
			t.Errorf("syftConfigOption refuses %q, which names no Syft configuration file", argument)
		}
	}
}

// TestReleaseSBOMsStayOffline keeps every SBOM behind
// scripts/reproducible-syft.sh, which normalizes the document, confines
// Syft's license lookup to the local module cache and names Syft's only
// configuration file itself, and keeps Syft's online enrichment out of the
// configuration. The wrapper refuses --enrich and a second --config itself,
// but only when GoReleaser runs it, in the CI snapshot or during a release;
// this finds them before either. GoReleaser's default command is syft
// itself, with --enrich all.
func TestReleaseSBOMsStayOffline(t *testing.T) {
	var config goreleaserConfig
	readGoReleaserConfig(t, &config)
	if len(config.SBOMs) == 0 {
		t.Fatal(".goreleaser.yaml generates no SBOMs; update this test")
	}
	for _, sbom := range config.SBOMs {
		if sbom.Cmd != "../scripts/reproducible-syft.sh" {
			t.Errorf(".goreleaser.yaml sboms entry %s runs %q, not ../scripts/reproducible-syft.sh", sbom.ID, sbom.Cmd)
		}
		for _, argument := range sbom.Args {
			argument = strings.TrimSpace(argument)
			if strings.HasPrefix(argument, "--enrich") {
				t.Errorf(".goreleaser.yaml sboms entry %s passes %q; Syft's enrichment looks licenses up on the network", sbom.ID, argument)
			}
			// Syft merges every file named with --config, or -c, into the
			// wrapper's own, enrich: lists included. syftConfigOption says
			// which arguments name one.
			if syftConfigOption.MatchString(argument) {
				t.Errorf(".goreleaser.yaml sboms entry %s passes %q; reproducible-syft.sh names Syft's configuration file itself", sbom.ID, argument)
			}
		}
		// The same option in the form of a variable, which GoReleaser
		// passes to the command when the entry sets it.
		for _, variable := range sbom.Env {
			if strings.HasPrefix(strings.TrimSpace(variable), "SYFT_ENRICH=") {
				t.Errorf(".goreleaser.yaml sboms entry %s sets %q; Syft's enrichment looks licenses up on the network", sbom.ID, variable)
			}
		}
	}
}

// TestReleaseWorkflowChoosesTheNotesRangeBeforeApproval keeps the choice of
// the release notes range where a tag that cannot make it fails early: in a
// job behind no environment, so before the tests and before anyone is asked
// to approve the signing. The signed build, whose changelog the draft release
// is created with, must then use that choice. Without it GoReleaser falls back
// to the nearest tag, which for a stable tag cut after a candidate covers only
// rc..stable.
func TestReleaseWorkflowChoosesTheNotesRangeBeforeApproval(t *testing.T) {
	release := releaseWorkflow(t)
	chooserName, chooser := "", -1
	for jobName, job := range release.Jobs {
		index := stepIndex(job, func(step workflowStep) bool {
			return strings.Contains(shellCode(step.Run), "bash scripts/previous-stable-tag.sh")
		})
		if index < 0 {
			continue
		}
		// With the choice made in two jobs, map order would decide which
		// one the checks below hold to the rule.
		if chooserName != "" {
			t.Fatalf("release.yml jobs %s and %s both run scripts/previous-stable-tag.sh; choose the release notes range once, in the job behind no environment",
				chooserName, jobName)
		}
		chooserName, chooser = jobName, index
	}
	if chooserName == "" {
		t.Fatal("release.yml no longer runs scripts/previous-stable-tag.sh; update this test")
	}
	if name := environmentName(release.Jobs[chooserName].Environment); name != "" {
		t.Errorf("release.yml chooses the release notes range in job %s, behind the %s environment; a tag without the script would fail only after approval",
			chooserName, name)
	}

	builds := 0
	for jobName, job := range release.Jobs {
		if !grantsWrite(jobPermissions(release, job), "id-token") {
			continue
		}
		for _, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "goreleaser/goreleaser-action@") {
				continue
			}
			builds++
			previous := fmt.Sprint(step.Env["GORELEASER_PREVIOUS_TAG"])
			index, output, ok := outputSource(release, job, previous, chooserName)
			written := false
			for _, line := range strings.Split(shellCode(release.Jobs[chooserName].Steps[chooser].Run), "\n") {
				written = written || strings.Contains(line, output+"=") && strings.Contains(line, "GITHUB_OUTPUT")
			}
			if !ok || index != chooser || !written {
				t.Errorf("release.yml job %s builds the release with GORELEASER_PREVIOUS_TAG %s, not the range job %s chose", jobName, previous, chooserName)
			}
		}
	}
	if builds == 0 {
		t.Fatal("no release.yml job that can sign runs GoReleaser; update this test")
	}
}
