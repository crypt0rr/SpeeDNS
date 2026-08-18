package version

// These values are replaced by the release build. Keeping useful development
// defaults makes `speedns version` helpful when running from source.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Values returns the build metadata as one stable tuple for CLI consumers.
func Values() (string, string, string) { return Version, Commit, Date }
