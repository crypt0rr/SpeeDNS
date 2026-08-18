package version

import "testing"

func TestDevelopmentVersionMetadataIsUsable(t *testing.T) {
	if Version == "" || Commit == "" || Date == "" {
		t.Fatalf("incomplete version metadata: %q/%q/%q", Version, Commit, Date)
	}
	if gotVersion, gotCommit, gotDate := Values(); gotVersion != Version || gotCommit != Commit || gotDate != Date {
		t.Fatalf("Values() = %q/%q/%q", gotVersion, gotCommit, gotDate)
	}
}
