// Package version holds build-time version information injected by ldflags.
package version

var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func String() string {
	return Version + " (" + Commit + ") built " + BuildDate
}
