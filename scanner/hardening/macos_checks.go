package hardening

import (
	"github.com/sentari-dev/sentari-agent/scanner/hardening/plist"
)

// These helpers turn already-read plist bytes into observation values. They are
// build-tag-free (portable, unit-testable on any OS); the darwin dispatcher in
// collect_darwin.go feeds them real /Library/Preferences bytes.

// macFirewallEnabled reads com.apple.alf's `globalstate` (0 = off, 1/2 = on).
// ok=false when the key is missing/malformed (=> the caller emits unknown).
func macFirewallEnabled(data []byte) (value string, ok bool) {
	root, err := plist.Parse(data)
	if err != nil {
		return "", false
	}
	n, ok := plist.Int(root, "globalstate")
	if !ok {
		return "", false
	}
	return boolStr(n >= 1), true
}

// macAutoUpdateEnabled reads com.apple.SoftwareUpdate's AutomaticCheckEnabled.
func macAutoUpdateEnabled(data []byte) (value string, ok bool) {
	root, err := plist.Parse(data)
	if err != nil {
		return "", false
	}
	b, ok := plist.Bool(root, "AutomaticCheckEnabled")
	if !ok {
		return "", false
	}
	return boolStr(b), true
}

// macScreenLock reads com.apple.screensaver's askForPassword (lock enabled) and
// askForPasswordDelay (grace seconds before the lock engages). Either may be
// absent.
func macScreenLock(data []byte) (enabled string, enabledOK bool, timeout string, timeoutOK bool) {
	root, err := plist.Parse(data)
	if err != nil {
		return "", false, "", false
	}
	if b, ok := plist.Bool(root, "askForPassword"); ok {
		enabled, enabledOK = boolStr(b), true
	}
	if n, ok := plist.Int(root, "askForPasswordDelay"); ok {
		timeout, timeoutOK = itoa(n), true
	}
	return enabled, enabledOK, timeout, timeoutOK
}

// itoa renders an int64 without importing strconv at every call site.
func itoa(n int64) string {
	// Small, allocation-light integer formatting.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
