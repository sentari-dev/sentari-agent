//go:build !windows

package scanner

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
)

// getFileOwner returns the username of the file owner on Unix systems.
// Returns empty string on any failure (permission denied, user not found, etc.).
func getFileOwner(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}

	u, err := user.LookupId(fmt.Sprintf("%d", stat.Uid))
	if err != nil {
		// If the user doesn't exist in /etc/passwd (e.g., container), return UID.
		return fmt.Sprintf("uid:%d", stat.Uid)
	}
	return u.Username
}
