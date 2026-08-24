package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestReportV1IsEmbeddedJSONSchema(t *testing.T) {
	contents := ReportV1()
	if len(contents) == 0 {
		t.Fatal("report schema is empty")
	}
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("report schema is not valid JSON: %v", err)
	}
	for _, field := range []string{"$schema", "$id", "title", "type", "$defs"} {
		if _, ok := document[field]; !ok {
			t.Fatalf("report schema is missing %q", field)
		}
	}
	if document["type"] != "object" || !strings.HasSuffix(document["$id"].(string), "/schema/report-v1.json") {
		t.Fatalf("unexpected report schema identity: %#v", document)
	}
	copyOfContents := ReportV1()
	copyOfContents[0] = 'x'
	if ReportV1()[0] == 'x' {
		t.Fatal("ReportV1 did not return an independent copy")
	}
}

// TestLiveResultsV1IsEmbeddedJSONSchema mirrors the report-v1 test for the
// live-results contract. The schema package is what lets Go tests check
// encoder output against the contract scripts/publish-live-results.py
// enforces, so the accessor needs the same independent-copy guarantee.
func TestLiveResultsV1IsEmbeddedJSONSchema(t *testing.T) {
	contents := LiveResultsV1()
	if len(contents) == 0 {
		t.Fatal("LiveResultsV1 returned no schema")
	}
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("live-results schema is not valid JSON: %v", err)
	}
	definitions, ok := document["$defs"].(map[string]any)
	if !ok {
		t.Fatal("live-results schema has no $defs")
	}
	if _, ok := definitions["stats"]; !ok {
		t.Fatal("live-results schema has no $defs/stats")
	}

	contents[0] = 'x'
	if LiveResultsV1()[0] == 'x' {
		t.Fatal("LiveResultsV1 did not return an independent copy")
	}
}

// TestRepositoryTracksNoBinaries fails if a compiled artifact is committed.
//
// A 14 MB scratch binary reached main in the v0.3.0 pre-release commit, swept
// in by a `git add -A` after an audit left a build in .gotmp/. Nothing caught
// it: gofmt, vet, staticcheck and the coverage gate all only look at Go source,
// and the earlier stray-file check grepped for .pyc and .patch by name.
//
// This matters more than tidiness. The Go module zip is immutable once
// proxy.golang.org fetches a tag, so a binary committed at a release tag can
// never be removed -- only superseded.
func TestRepositoryTracksNoBinaries(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("git ls-files unavailable: %v", err)
	}

	// Files that are legitimately non-text. Keep this list short and explicit:
	// every entry is a decision that something binary belongs in the tree.
	allowed := map[string]bool{}

	var offenders []string
	for _, name := range strings.Split(string(listed), "\x00") {
		if name == "" || allowed[name] {
			continue
		}
		path := filepath.Join(root, name)
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			continue
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		// A NUL byte in the first 8 KB is the same heuristic git itself uses to
		// decide a blob is binary.
		head := content
		if len(head) > 8192 {
			head = head[:8192]
		}
		if bytes.IndexByte(head, 0) >= 0 {
			offenders = append(offenders, fmt.Sprintf("%s (%d bytes)", name, len(content)))
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("compiled or binary artifacts are tracked:\n  %s", strings.Join(offenders, "\n  "))
	}
}

// TestTrackedFilesHonourGitignore fails if a tracked file matches .gitignore.
//
// The pattern this closes has now recurred three times: a .pyc and a .patch in
// #143, a 14 MB binary in #163, and a 46-byte scratch .log in #165 -- every one
// swept in by a `git add -A` that did not stop to look. Each time the response
// was to add the offending NAME to .gitignore, which is a blacklist and so is
// always one step behind the next kind of scratch file.
//
// This checks the property instead: git already knows what the project has
// declared it never wants, so anything tracked that also matches .gitignore is
// a mistake by the project's own definition. It needs no list of its own, and
// it grows automatically whenever .gitignore does.
func TestTrackedFilesHonourGitignore(t *testing.T) {
	root := repositoryRoot(t)
	tracked := gitOutput(t, root, "ls-files", "-z")
	if tracked == "" {
		return
	}

	// check-ignore --no-index asks the question for paths regardless of the
	// index, which is the whole point: a tracked file normally shortcuts the
	// ignore rules, so without this flag git reports nothing.
	command := exec.Command("git", "-C", root, "check-ignore", "--no-index", "--stdin", "-z", "-v")
	command.Stdin = strings.NewReader(tracked)
	output, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		// Exit status 1 means "nothing matched", which is the healthy answer.
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return
		}
		t.Skipf("git check-ignore unavailable: %v", err)
	}

	var offenders []string
	fields := strings.Split(strings.TrimRight(string(output), "\x00"), "\x00")
	// -v -z emits four NUL-separated fields per match: source, line, pattern, path.
	for index := 0; index+3 < len(fields); index += 4 {
		offenders = append(offenders, fmt.Sprintf("%s (matches %q from %s:%s)",
			fields[index+3], fields[index+2], fields[index], fields[index+1]))
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("these files are tracked but .gitignore says they are unwanted:\n  %s\n\nRemove them with `git rm --cached <path>`.",
			strings.Join(offenders, "\n  "))
	}
}

// TestTrackedFilesCarryNoLocalPaths fails if a tracked file embeds an absolute
// home directory.
//
// The .pyc removed in #163 leaked /home/<user>/projects-claude/SpeeDNS into the
// tree, and was caught only because it happened to be binary. The same leak in
// a text file -- a pasted log, a captured error, a checked-in profile -- would
// pass every gate today. The script that .pyc was compiled from ships a regex
// whose entire job is redacting these paths from published output, so the
// project already treats them as something that must not escape.
func TestTrackedFilesCarryNoLocalPaths(t *testing.T) {
	root := repositoryRoot(t)
	tracked := gitOutput(t, root, "ls-files", "-z")

	// Matches a real home directory, not the string "/home/" in prose. The
	// user component must look like a username and be followed by a path
	// separator, so documentation saying "under /home/" does not fire.
	localPath := regexp.MustCompile(`(?:/home/|/Users/|\\Users\\)[A-Za-z0-9._-]{2,32}[/\\]`)

	var offenders []string
	for _, name := range strings.Split(strings.TrimRight(tracked, "\x00"), "\x00") {
		if name == "" {
			continue
		}
		// This test's own source necessarily contains the pattern.
		if name == "schema/schema_test.go" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue
		}
		if match := localPath.Find(content); match != nil {
			offenders = append(offenders, fmt.Sprintf("%s contains %q", name, string(match)))
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("these tracked files embed an absolute local path:\n  %s", strings.Join(offenders, "\n  "))
	}
}

// TestTrackedFilesCarryNoPrivateKeys is the one credential rule kept in-tree.
//
// A general secret scanner is a token zoo chasing a moving target; that job
// belongs to GitHub push protection, which blocks the push rather than failing
// after the commit. A PEM private key is different: the header is unambiguous
// and a real key is followed by a substantial base64 body, so requiring both
// gives a rule with no list to maintain and no false positives on prose that
// merely quotes the header.
func TestTrackedFilesCarryNoPrivateKeys(t *testing.T) {
	root := repositoryRoot(t)
	tracked := gitOutput(t, root, "ls-files", "-z")
	privateKey := regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{100,}`)

	var offenders []string
	for _, name := range strings.Split(strings.TrimRight(tracked, "\x00"), "\x00") {
		if name == "" || name == "schema/schema_test.go" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue
		}
		if privateKey.Match(content) {
			offenders = append(offenders, name)
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("these tracked files contain a private key:\n  %s", strings.Join(offenders, "\n  "))
	}
}

// repositoryRoot resolves the repository root, or skips when git is absent --
// unless this is CI, where an absent tool must not silently disable a gate.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("git"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("git is required to run the repository hygiene gates in CI: %v", err)
		}
		t.Skipf("git unavailable: %v", err)
	}
	return root
}

func gitOutput(t *testing.T, root string, args ...string) string {
	t.Helper()
	output, err := exec.Command("git", append([]string{"-C", root}, args...)...).Output()
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("git %v failed in CI: %v", args, err)
		}
		t.Skipf("git %v failed: %v", args, err)
	}
	return string(output)
}
