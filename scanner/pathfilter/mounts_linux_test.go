//go:build linux

package pathfilter

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLinuxNetworkMagic_positiveAndNegative pins the classifier table —
// the map lookup IsNetworkFilesystem performs once statfs has reported a
// filesystem type:
//
//	_, isNetwork := linuxNetworkMagic[int64(stat.Type)]
//
// It drives that exact expression with the documented network magic
// numbers (positive) and with common local-filesystem magics (negative),
// so dropping NFS/CIFS or accidentally adding ext4/tmpfs fails here.
// The end-to-end positive return of IsNetworkFilesystem itself is
// covered by TestIsNetworkFilesystem_networkMagicViaSeam below. Runs in
// the linux CI job.
func TestLinuxNetworkMagic_positiveAndNegative(t *testing.T) {
	// classify mirrors the exact expression in IsNetworkFilesystem so the
	// test exercises the real decision rather than a re-implementation.
	classify := func(magic int64) bool {
		_, isNetwork := linuxNetworkMagic[magic]
		return isNetwork
	}

	network := []struct {
		name  string
		magic int64
	}{
		{"NFS_SUPER_MAGIC", 0x6969},
		{"CIFS/SMB2_SUPER_MAGIC", 0xff534d42},
		{"SMB_SUPER_MAGIC", 0x517b},
		{"AFS_SUPER_MAGIC", 0x5346414f},
		{"FUSE_SUPER_MAGIC", 0x65735546},
		{"V9FS_MAGIC", 0x01021997},
		{"AUTOFS_SUPER_MAGIC", 0x0187},
	}
	for _, c := range network {
		t.Run("network/"+c.name, func(t *testing.T) {
			if !classify(c.magic) {
				t.Fatalf("magic %#x (%s) must classify as network", c.magic, c.name)
			}
		})
	}

	local := []struct {
		name  string
		magic int64
	}{
		{"EXT2/3/4_SUPER_MAGIC", 0xEF53},
		{"TMPFS_MAGIC", 0x01021994},
		{"SQUASHFS_MAGIC", 0x73717368}, // intentionally excluded per source docs
		{"BTRFS_SUPER_MAGIC", 0x9123683e},
		{"XFS_SUPER_MAGIC", 0x58465342},
	}
	for _, c := range local {
		t.Run("local/"+c.name, func(t *testing.T) {
			if classify(c.magic) {
				t.Fatalf("magic %#x (%s) must NOT classify as network", c.magic, c.name)
			}
		})
	}
}

// fakeStatfs swaps the statfsFn seam for a fake and restores the real
// unix.Statfs via t.Cleanup. Not safe for t.Parallel (package-level
// seam, matching the repo's existing seam conventions).
func fakeStatfs(t *testing.T, fn func(path string, stat *unix.Statfs_t) error) {
	t.Helper()
	orig := statfsFn
	statfsFn = fn
	t.Cleanup(func() { statfsFn = orig })
}

// TestIsNetworkFilesystem_networkMagicViaSeam exercises the END-TO-END
// positive return of IsNetworkFilesystem: the statfsFn seam reports an
// NFS filesystem type and the function must classify the path as
// network. Also covers the negative (ext4) and error-propagation paths
// through the same seam, so all three return branches of the real
// function body are executed.
func TestIsNetworkFilesystem_networkMagicViaSeam(t *testing.T) {
	t.Run("nfs magic classifies as network", func(t *testing.T) {
		fakeStatfs(t, func(path string, stat *unix.Statfs_t) error {
			stat.Type = 0x6969 // NFS_SUPER_MAGIC
			return nil
		})
		isNet, err := IsNetworkFilesystem("/mnt/nfs-share/project")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isNet {
			t.Fatal("NFS-typed mount must classify as a network filesystem")
		}
	})

	t.Run("ext4 magic classifies as local", func(t *testing.T) {
		fakeStatfs(t, func(path string, stat *unix.Statfs_t) error {
			stat.Type = 0xEF53 // EXT4_SUPER_MAGIC
			return nil
		})
		isNet, err := IsNetworkFilesystem("/srv/app")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isNet {
			t.Fatal("ext4-typed mount must NOT classify as a network filesystem")
		}
	})

	t.Run("statfs error propagates as (false, err)", func(t *testing.T) {
		sentinel := errors.New("statfs boom")
		fakeStatfs(t, func(path string, stat *unix.Statfs_t) error {
			return sentinel
		})
		isNet, err := IsNetworkFilesystem("/does/not/matter")
		if !errors.Is(err, sentinel) {
			t.Fatalf("error not propagated: got %v", err)
		}
		if isNet {
			t.Fatal("error path must return isNetwork=false")
		}
	})
}

// TestShouldSkipDir_networkExclusionBranch covers ShouldSkipDir's
// ExcludeNetworkPaths → IsNetworkFilesystem branch (pathfilter.go), which no
// other test drives. The path is not cloud-synced (false on linux) so control
// reaches the opt-in network branch: with the flag ON and the statfsFn seam
// reporting an NFS magic the walker must prune the subtree; with the flag OFF
// the same path must NOT be pruned, since network exclusion is opt-in.
func TestShouldSkipDir_networkExclusionBranch(t *testing.T) {
	const netPath = "/mnt/nfs-share/project"

	// Restore the package-level toggle regardless of sub-test outcome.
	orig := ExcludeNetworkPaths
	t.Cleanup(func() { ExcludeNetworkPaths = orig })

	// statfsFn reports a network filesystem (NFS) for the path under test;
	// fakeStatfs restores the real syscall on cleanup.
	fakeStatfs(t, func(path string, stat *unix.Statfs_t) error {
		stat.Type = 0x6969 // NFS_SUPER_MAGIC
		return nil
	})

	t.Run("flag on → network path is skipped", func(t *testing.T) {
		ExcludeNetworkPaths = true
		if !ShouldSkipDir(netPath) {
			t.Fatalf("ShouldSkipDir(%q) = false; opt-in network exclusion must prune an NFS mount", netPath)
		}
	})

	t.Run("flag off → network path is not skipped", func(t *testing.T) {
		ExcludeNetworkPaths = false
		if ShouldSkipDir(netPath) {
			t.Fatalf("ShouldSkipDir(%q) = true; network exclusion is opt-in and must not fire when the flag is off", netPath)
		}
	})
}

// TestIsNetworkFilesystem_linuxLocalPath is a live smoke test of the real
// syscall path (no seam): "/" on a linux CI runner is a local
// filesystem, so the statfs call must succeed and the result must be
// non-network. This covers the real unix.Statfs call + int64(stat.Type)
// conversion glue.
func TestIsNetworkFilesystem_linuxLocalPath(t *testing.T) {
	isNet, err := IsNetworkFilesystem("/")
	if err != nil {
		t.Fatalf("Statfs / failed unexpectedly: %v", err)
	}
	if isNet {
		t.Fatal("/ must not classify as a network filesystem on the CI runner")
	}
}
