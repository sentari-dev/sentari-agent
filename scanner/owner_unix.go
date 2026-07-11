//go:build !windows

package scanner

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// passwdPath is the local user database consulted as a CGO_ENABLED=0 fallback
// when os/user cannot resolve a uid (see getFileOwner).  A package var so a test
// can point it at a fixture; production always reads the real /etc/passwd.
var passwdPath = "/etc/passwd"

// maxPasswdSize caps the /etc/passwd read.  A local passwd file is a few KiB;
// 4 MiB is a generous bound that still refuses a pathological/hostile file
// without loading it whole.
const maxPasswdSize = 4 << 20

// getFileOwner returns the username of the file owner on Unix systems.
// Returns empty string on any failure (permission denied, user not found, etc.).
//
// NSS LIMITATION (CGO_ENABLED=0):  the charter builds a static binary
// (CGO_ENABLED=0), which disables cgo and therefore the platform NSS backends
// (nss_ldap, sssd, nss_systemd, …) that os/user's cgo path would otherwise use.
// The pure-Go os/user then resolves uids ONLY against the local /etc/passwd.
// On an LDAP/AD-joined host a directory user that owns a scanned directory has
// no /etc/passwd entry, so os.LookupId misses and this function degrades to the
// numeric "uid:<N>" form.  This is an inherent, documented tradeoff of the
// static-binary charter, not a silent bug — see also the installer_user field
// contract in Result (types.go), which carries the same "uid:<N>" fallback.
//
// Best-effort recovery: on the os/user miss we parse /etc/passwd directly for a
// matching uid before falling back.  That recovers LOCAL users on any host
// (identical to what os/user's pure-Go path does, but robust to it having been
// short-circuited).  Directory (LDAP/AD) users still degrade to "uid:<N>"
// because they are, by definition, absent from the local file.
func getFileOwner(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}

	uid := stat.Uid
	if u, err := user.LookupId(fmt.Sprintf("%d", uid)); err == nil {
		return u.Username
	}

	// os/user missed.  Under CGO_ENABLED=0 that can mean NSS was never
	// consulted, so try the local passwd file directly before giving up on a
	// name.  A directory-only user simply will not be found here and falls
	// through to the numeric form below (documented degradation).
	if name := lookupPasswdName(uid); name != "" {
		return name
	}

	// If the user doesn't exist in /etc/passwd (e.g. a container image with no
	// passwd entry, or a directory user under CGO_ENABLED=0), return the uid.
	return fmt.Sprintf("uid:%d", uid)
}

// lookupPasswdName parses passwdPath for an entry whose uid field equals uid and
// returns its username, or "" if not found / unreadable.  It reads via safeio
// (symlink- and size-guarded) and tolerates malformed lines, so a damaged or
// hostile passwd file degrades to the numeric fallback rather than misresolving.
func lookupPasswdName(uid uint32) string {
	data, err := safeio.ReadFile(passwdPath, maxPasswdSize)
	if err != nil {
		return ""
	}
	want := strconv.FormatUint(uint64(uid), 10)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[2] == want && fields[0] != "" {
			return fields[0]
		}
	}
	return ""
}
