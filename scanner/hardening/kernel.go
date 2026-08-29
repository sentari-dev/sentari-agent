package hardening

import (
	"sort"
	"strings"
)

// kernelSysctls maps each kernel.* observation slug to its /proc/sys relative
// path. These are the 8 keys in the contract's v1 vocabulary.
var kernelSysctls = map[string]string{
	"randomize_va_space": "kernel/randomize_va_space",
	"ip_forward":         "net/ipv4/ip_forward",
	"accept_redirects":   "net/ipv4/conf/all/accept_redirects",
	"send_redirects":     "net/ipv4/conf/all/send_redirects",
	"tcp_syncookies":     "net/ipv4/tcp_syncookies",
	"protected_symlinks": "fs/protected_symlinks",
	"kptr_restrict":      "kernel/kptr_restrict",
	"rp_filter":          "net/ipv4/conf/all/rp_filter",
}

// collectKernel reads each sysctl scalar under procSysRoot ("/proc/sys" in
// production, a fixture dir in tests) and emits one kernel.* observation. A
// missing scalar (e.g. a namespaced/hardened /proc) is emitted unknown.
func collectKernel(procSysRoot string) []Observation {
	slugs := make([]string, 0, len(kernelSysctls))
	for s := range kernelSysctls {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)

	out := make([]Observation, 0, len(slugs))
	for _, slug := range slugs {
		key := familyKernel + "." + slug
		path := procSysRoot + "/" + kernelSysctls[slug]
		data, sha, reason := readSource(path, maxProcFileSize)
		if reason != "" {
			out = append(out, obsError(key, familyKernel, path, reason))
			continue
		}
		// A sysctl scalar is a single whitespace-delimited value (rp_filter/
		// redirects can be a tab-separated vector on some kernels — keep the
		// first field, which is the `all` scope we pointed at).
		val := strings.TrimSpace(string(data))
		if f := strings.Fields(val); len(f) > 0 {
			val = f[0]
		}
		out = append(out, obsValue(key, familyKernel, val, path, sha))
	}
	return out
}
