package hardening

import "testing"

// These parsers are build-tag-free: they turn already-read plist bytes into
// observation values, so they run and are covered on any host (including this
// darwin/linux CI box) without a macOS source tree.

func plistDict(body string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>` + body + `</dict></plist>`)
}

func TestMacFirewallEnabled(t *testing.T) {
	// globalstate 1 => on.
	if v, ok := macFirewallEnabled(plistDict(`<key>globalstate</key><integer>1</integer>`)); !ok || v != "true" {
		t.Errorf("globalstate=1 => (%q,%v), want (true,true)", v, ok)
	}
	// globalstate 2 (blocking mode) => on.
	if v, ok := macFirewallEnabled(plistDict(`<key>globalstate</key><integer>2</integer>`)); !ok || v != "true" {
		t.Errorf("globalstate=2 => (%q,%v)", v, ok)
	}
	// globalstate 0 => off.
	if v, ok := macFirewallEnabled(plistDict(`<key>globalstate</key><integer>0</integer>`)); !ok || v != "false" {
		t.Errorf("globalstate=0 => (%q,%v)", v, ok)
	}
	// Missing key => ok=false (caller emits unknown).
	if _, ok := macFirewallEnabled(plistDict(`<key>other</key><integer>1</integer>`)); ok {
		t.Error("missing globalstate must yield ok=false")
	}
	// Unparseable => ok=false.
	if _, ok := macFirewallEnabled([]byte("not a plist")); ok {
		t.Error("garbage plist must yield ok=false")
	}
}

func TestMacAutoUpdateEnabled(t *testing.T) {
	if v, ok := macAutoUpdateEnabled(plistDict(`<key>AutomaticCheckEnabled</key><true/>`)); !ok || v != "true" {
		t.Errorf("true => (%q,%v)", v, ok)
	}
	if v, ok := macAutoUpdateEnabled(plistDict(`<key>AutomaticCheckEnabled</key><false/>`)); !ok || v != "false" {
		t.Errorf("false => (%q,%v)", v, ok)
	}
	if _, ok := macAutoUpdateEnabled(plistDict(`<key>Other</key><true/>`)); ok {
		t.Error("missing key must yield ok=false")
	}
	if _, ok := macAutoUpdateEnabled([]byte("garbage")); ok {
		t.Error("garbage plist must yield ok=false")
	}
}

func TestMacScreenLock(t *testing.T) {
	// askForPassword stored as <integer>1</integer> (Apple stores bools both
	// ways); Bool coerces. askForPasswordDelay is grace seconds.
	en, enOK, to, toOK := macScreenLock(plistDict(
		`<key>askForPassword</key><integer>1</integer><key>askForPasswordDelay</key><integer>300</integer>`))
	if !enOK || en != "true" {
		t.Errorf("enabled => (%q,%v), want (true,true)", en, enOK)
	}
	if !toOK || to != "300" {
		t.Errorf("timeout => (%q,%v), want (300,true)", to, toOK)
	}

	// Missing both keys => both ok=false.
	en, enOK, to, toOK = macScreenLock(plistDict(`<key>moduleName</key><string>Flurry</string>`))
	if enOK || toOK || en != "" || to != "" {
		t.Errorf("absent keys => (%q,%v,%q,%v), want empties+false", en, enOK, to, toOK)
	}

	// Unparseable => all false.
	if _, enOK, _, toOK := macScreenLock([]byte("garbage")); enOK || toOK {
		t.Error("garbage plist must yield all-false")
	}
}

func TestItoa(t *testing.T) {
	cases := map[int64]string{0: "0", 5: "5", 300: "300", -42: "-42", 1234567890: "1234567890"}
	for n, want := range cases {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d)=%q, want %q", n, got, want)
		}
	}
}
