package containers

import "testing"

// TestParseWhiteoutMarker — Task 2 Step 1 of the container-scanner
// plan.  Recognises three marker conventions across OCI + aufs +
// overlayfs; every real image the fleet will meet uses one of them.
// A regression here would silently fail to hide lower-layer paths
// in the merged view, producing ghost package records.
func TestParseWhiteoutMarker(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantKind   WhiteoutKind
		wantTarget string
	}{
		// --- plain whiteouts ---------------------------------------
		{"plain whiteout on file", ".wh.foo", PlainWhiteout, "foo"},
		{"plain whiteout on dir", ".wh.some-directory", PlainWhiteout, "some-directory"},
		{"plain whiteout with dots in target", ".wh.file.with.dots", PlainWhiteout, "file.with.dots"},
		{"plain whiteout with dashes", ".wh.lib-dev", PlainWhiteout, "lib-dev"},

		// --- opaque-dir marker -------------------------------------
		{"opaque dir marker", ".wh..wh..opq", OpaqueDirWhiteout, ""},

		// --- hardlink whiteout -------------------------------------
		{"hardlink whiteout short hash", ".wh..wh..plnk.abc123", HardlinkWhiteout, ""},
		{"hardlink whiteout long hash", ".wh..wh..plnk.deadbeef0001", HardlinkWhiteout, ""},

		// --- unknown ``.wh..wh.`` meta-marker ----------------------
		// Not a marker we know; still refuse to emit it as content.
		{"unknown meta marker", ".wh..wh..xyz", HardlinkWhiteout, ""},

		// --- non-whiteouts -----------------------------------------
		{"regular file", "foo.txt", NotWhiteout, ""},
		{"regular dotfile", ".gitignore", NotWhiteout, ""},
		{"file starting with wh but no dot", "whatever", NotWhiteout, ""},
		{"starts with .w but not .wh.", ".w-thing", NotWhiteout, ""},
		{"empty string", "", NotWhiteout, ""},
		{"just .wh. prefix empty target", ".wh.", PlainWhiteout, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotKind, gotTarget := ParseWhiteoutMarker(tc.input)
			if gotKind != tc.wantKind {
				t.Errorf("kind: got %v, want %v", gotKind, tc.wantKind)
			}
			if gotTarget != tc.wantTarget {
				t.Errorf("target: got %q, want %q", gotTarget, tc.wantTarget)
			}
		})
	}
}
