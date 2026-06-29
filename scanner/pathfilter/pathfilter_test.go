package pathfilter

import (
	"runtime"
	"testing"
)

func TestIsCloudSyncedPath_macos(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cloud-path detection is darwin-only for now")
	}
	cases := []struct {
		path string
		want bool
	}{
		// iCloud Drive
		{"/Users/alice/Library/Mobile Documents/com~apple~CloudDocs/work/.venv", true},
		// Trailing-segment match (no further nesting)
		{"/Users/alice/Library/Mobile Documents", true},
		// CloudStorage providers
		{"/Users/bob/Library/CloudStorage/Dropbox-Personal/code", true},
		{"/Users/bob/Library/CloudStorage/GoogleDrive-user@example.com/projects", true},
		{"/Users/bob/Library/CloudStorage/OneDrive-Acme/repo/.venv", true},
		// Anything else under Library is fine
		{"/Users/alice/Library/Caches/python", false},
		{"/Users/alice/Library/Application Support/Sentari", false},
		// Outside Library entirely
		{"/Users/alice/Documents/repo/.venv", false},
		{"/opt/homebrew/Cellar/python@3.13/3.13.7/Frameworks", false},
		{"/srv/app/.venv", false},
		// Relative paths and empty input
		{"", false},
		{"Library/Mobile Documents/x", false},
		// Different /Users layout (someone's username happens to be "Library")
		{"/Users/Library/Documents/.venv", false},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := IsCloudSyncedPath(c.path); got != c.want {
				t.Fatalf("IsCloudSyncedPath(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestIsCloudSyncedPath_nonDarwinAlwaysFalse(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("only meaningful off-darwin")
	}
	if IsCloudSyncedPath("/Users/alice/Library/Mobile Documents/x") {
		t.Fatal("non-darwin must return false for cloud-prefixed paths")
	}
}

func TestIsNetworkFilesystem_localPathIsNotNetwork(t *testing.T) {
	// "/tmp" is local on every supported OS.  On non-darwin the stub
	// returns (false, nil) regardless; on darwin Statfs returns the
	// real fstype (apfs / hfs / tmpfs) which is not in networkFstypes.
	isNet, err := IsNetworkFilesystem("/tmp")
	if err != nil {
		t.Fatalf("Statfs /tmp failed unexpectedly: %v", err)
	}
	if isNet {
		t.Fatal("/tmp must not classify as a network filesystem")
	}
}

func TestExcludeNetworkPaths_defaultFalse(t *testing.T) {
	// The toggle's default value is what the agent ships with; a
	// future change that switches it on by default needs to update
	// this test deliberately.
	if ExcludeNetworkPaths {
		t.Fatal("ExcludeNetworkPaths must default to false (opt-in)")
	}
}
