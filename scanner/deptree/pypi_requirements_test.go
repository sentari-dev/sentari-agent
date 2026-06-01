package deptree

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseRequirementsTxt_PEP440Specifiers exercises every PEP 440
// specifier the regex now accepts.  Pre-fix only "==" was matched; any
// other operator silently dropped the line and the server-side drift
// detector then flagged that dep as "removed" every single scan.
//
// Post-fix all specifiers parse.  Only "==" / "===" lines emit
// Resolved=true (a concrete pinned version we can correlate against);
// every other operator emits Resolved=false with the raw specifier as
// the version so operators still see the line and the drift detector
// knows the dep is intentionally unpinned.
func TestParseRequirementsTxt_PEP440Specifiers(t *testing.T) {
	body := `# project requirements covering the PEP 440 zoo
requests==2.31.0
urllib3>=1.26
flask[async]>=2.0
django~=4.2.0
boto3!=1.34.0
typing-extensions>4.0
six<2.0
mypkg===1.0.0+local
bare-name
psycopg2-binary>=2.9 ; python_version >= "3.8"
# comment line
-r dev-requirements.txt
--hash=sha256:abc123
`
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	edges, err := ParseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}

	type want struct {
		name     string
		version  string
		resolved bool
	}
	// Each case maps a PEP 440 spec to the expected (version, resolved)
	// emission.  Pinned (== / ===) → resolved=true.  Every other operator
	// → resolved=false with the raw specifier as the version string.
	cases := []want{
		{"requests", "2.31.0", true},
		{"urllib3", ">=1.26", false},
		{"flask", ">=2.0", false},
		{"django", "~=4.2.0", false},
		{"boto3", "!=1.34.0", false},
		{"typing-extensions", ">4.0", false},
		{"six", "<2.0", false},
		{"mypkg", "1.0.0+local", true},
		{"bare-name", "", false},
		{"psycopg2-binary", ">=2.9", false},
	}
	for _, c := range cases {
		e, ok := byChild[c.name]
		if !ok {
			t.Errorf("missing %q in parsed edges; got names=%v (full edges=%+v)", c.name, keysOfEdges(byChild), edges)
			continue
		}
		if e.ChildVersion != c.version {
			t.Errorf("%q: version=%q want %q", c.name, e.ChildVersion, c.version)
		}
		if e.Resolved != c.resolved {
			t.Errorf("%q: Resolved=%v want %v", c.name, e.Resolved, c.resolved)
		}
	}

	// "-r dev-requirements.txt" and comment lines must NOT appear.
	for _, banned := range []string{"-r", "dev-requirements.txt", "comment", "--hash"} {
		if _, ok := byChild[banned]; ok {
			t.Errorf("unexpected entry %q in parsed edges", banned)
		}
	}

	// Flask's extras (`[async]`) must be stripped from the emitted name.
	if _, ok := byChild["flask[async]"]; ok {
		t.Errorf(`emitted name still contains extras: "flask[async]" should be "flask"`)
	}
}

// TestParseRequirementsTxt_PinnedFixturePreservesBehaviour proves the
// existing requirements.txt fixture (only "==" lines) still parses
// identically — no regression on the pinned-only path.
func TestParseRequirementsTxt_PinnedFixturePreservesBehaviour(t *testing.T) {
	edges, err := ParseRequirementsTxt(filepath.Join("testdata", "pypi", "requirements", "requirements.txt"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges (skip -r and comments), got %d: %+v", len(edges), edges)
	}
	for _, e := range edges {
		if !e.Resolved {
			t.Errorf("%q (==): Resolved must remain true on pinned lines (got false); edge=%+v", e.ChildName, e)
		}
	}
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}
	if e, ok := byChild["requests"]; !ok || e.ChildVersion != "2.31.0" {
		t.Errorf("requests edge wrong: %+v", e)
	}
	if e, ok := byChild["urllib3"]; !ok || e.ChildVersion != "2.0.7" {
		t.Errorf("urllib3 edge wrong: %+v", e)
	}
}

func keysOfEdges(m map[string]DepEdge) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
