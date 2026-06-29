//go:build enterprise

package main

import "testing"

func TestScanRootDeniedForOS(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		goos   string
		denied bool
	}{
		// POSIX
		{"posix etc exact", "/etc", "linux", true},
		{"posix etc child", "/etc/ssh", "linux", true},
		{"posix proc", "/proc/1", "linux", true},
		{"posix allowed opt", "/opt/app", "linux", false}, // /opt not denied
		{"posix allowed srv", "/srv/data", "linux", false},
		{"posix etcfoo not a child", "/etcfoo", "linux", false},

		// Windows — case-insensitive, both separators
		{"win system32 backslash", `C:\Windows\System32`, "windows", true},
		{"win windows exact", `C:\Windows`, "windows", true},
		{"win program files", `C:\Program Files\app`, "windows", true},
		{"win programdata forward slash", "C:/ProgramData/sentari", "windows", true},
		{"win lowercase drive", `c:\windows\system32`, "windows", true},
		{"win allowed user dir", `C:\Users\alice\project`, "windows", false},
		{"win allowed other drive", `D:\code`, "windows", false},
		{"win windowsfoo not a child", `C:\Windowsfoo`, "windows", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanRootDeniedForOS(tc.path, tc.goos); got != tc.denied {
				t.Errorf("scanRootDeniedForOS(%q, %q) = %v, want %v", tc.path, tc.goos, got, tc.denied)
			}
		})
	}
}
