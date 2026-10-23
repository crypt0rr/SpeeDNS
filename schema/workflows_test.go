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
	if !strings.Contains(job.If, "github.event.release.prerelease") {
		t.Errorf("homebrew.yml publish job does not skip prerelease events: if: %q", job.If)
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
}
