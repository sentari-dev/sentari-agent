package scanner

import "testing"

func TestNodeModulesAncestor(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Flat layout: npm classic / yarn / pnpm-hoisted.
		{"/a/b/node_modules/lodash", "/a/b/node_modules"},
		// Scoped: unwinds two levels.
		{"/a/b/node_modules/@scope/pkg", "/a/b/node_modules"},
		// Nested transitive — returns the *nearest* node_modules.
		{"/a/node_modules/foo/node_modules/bar", "/a/node_modules/foo/node_modules"},
		// IDE-extension bundle (the case this fix is for).
		{"/Users/x/.cursor/extensions/ext/dist/node_modules/@aminya/node-gyp-build", "/Users/x/.cursor/extensions/ext/dist/node_modules"},
		// Trailing slash is tolerated (filepath.Clean strips it).
		{"/a/b/node_modules/lodash/", "/a/b/node_modules"},
		// No node_modules ancestor.
		{"/a/b/c", ""},
		// Edge: empty / "/" / ".".
		{"", ""},
		{"/", ""},
		{".", ""},
	}
	for _, c := range cases {
		if got := nodeModulesAncestor(c.in); got != c.want {
			t.Errorf("nodeModulesAncestor(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
