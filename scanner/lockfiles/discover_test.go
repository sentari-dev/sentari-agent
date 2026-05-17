package lockfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverInRoot_findsKnownLockfiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{"lockfileVersion":3,"packages":{"":{"name":"a"},"node_modules/foo":{"version":"1.0.0"}}}`)
	mustWrite(t, filepath.Join(root, "subproject", "pom.xml"), `<project xmlns="http://maven.apache.org/POM/4.0.0"></project>`)
	mustWrite(t, filepath.Join(root, "requirements.txt"), "requests==2.31.0\nurllib3==2.0.7\n# comment\n")

	results, err := DiscoverInRoot(root)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 lockfiles, got %d: %+v", len(results), results)
	}

	byFormat := map[string]deptreeMeta{}
	for _, r := range results {
		byFormat[r.Format] = deptreeMeta{Format: r.Format, Ecosystem: r.Ecosystem, SHA256: r.SHA256, Count: r.DeclaredPackagesCount}
	}
	if m, ok := byFormat["package_lock_v3"]; !ok || m.Ecosystem != "npm" {
		t.Errorf("package_lock_v3 missing or wrong ecosystem: %+v", m)
	}
	if m, ok := byFormat["pom_xml"]; !ok || m.Ecosystem != "maven" {
		t.Errorf("pom_xml missing: %+v", m)
	}
	if m, ok := byFormat["requirements_txt"]; !ok || m.Ecosystem != "pypi" || m.Count != 2 {
		t.Errorf("requirements_txt wrong: %+v (want count=2)", m)
	}
	if m := byFormat["package_lock_v3"]; len(m.SHA256) != 64 {
		t.Errorf("sha256 should be 64 hex chars, got %d: %q", len(m.SHA256), m.SHA256)
	}
}

func TestDiscoverInRoot_skipsNodeModules(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{"lockfileVersion":3,"packages":{}}`)
	// node_modules contains a nested lockfile we should NOT discover.
	mustWrite(t, filepath.Join(root, "node_modules", "some-dep", "package-lock.json"), `{"lockfileVersion":3,"packages":{}}`)

	results, err := DiscoverInRoot(root)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 lockfile (node_modules should be skipped), got %d: %+v", len(results), results)
	}
}

func TestDiscoverInRoot_skipsCommonNoiseDirs(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{".git", ".venv", "target", "build", "dist"} {
		mustWrite(t, filepath.Join(root, dir, "pom.xml"), `<project xmlns="http://maven.apache.org/POM/4.0.0"></project>`)
	}
	mustWrite(t, filepath.Join(root, "pom.xml"), `<project xmlns="http://maven.apache.org/POM/4.0.0"></project>`)

	results, err := DiscoverInRoot(root)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 pom.xml (skip dirs filtered), got %d: %+v", len(results), results)
	}
}

func TestDiscoverInRoot_sha256MatchesContent(t *testing.T) {
	root := t.TempDir()
	content := `{"lockfileVersion":3,"packages":{}}`
	mustWrite(t, filepath.Join(root, "package-lock.json"), content)

	results, err := DiscoverInRoot(root)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	h := sha256.Sum256([]byte(content))
	want := hex.EncodeToString(h[:])
	if results[0].SHA256 != want {
		t.Errorf("sha256 mismatch: got %s, want %s", results[0].SHA256, want)
	}
}

func TestDetectPackageLockVersion(t *testing.T) {
	root := t.TempDir()
	cases := map[string]string{
		`{"lockfileVersion":2,"packages":{}}`: "package_lock_v2",
		`{"lockfileVersion":3,"packages":{}}`: "package_lock_v3",
		// v1 is intentionally dropped from the v3 payload (no enum
		// entry on the server; silently remapping to v3 used to
		// produce downstream parser warnings).  The empty-string
		// sentinel is buildMeta's signal to translate into
		// errSkipLockfile.
		`{"lockfileVersion":1,"packages":{}}`: "",
	}
	for content, want := range cases {
		p := filepath.Join(root, "package-lock.json")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := detectPackageLockVersion(p)
		if err != nil {
			t.Errorf("detect failed: %v", err)
			continue
		}
		if got != want {
			t.Errorf("for content %q: got %q, want %q", content, got, want)
		}
	}
}

// TestDiscoverInRoot_skipsV1PackageLock confirms that a v1
// package-lock.json drops out of the discovered metadata silently
// (no entry, no error).
func TestDiscoverInRoot_skipsV1PackageLock(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{"lockfileVersion":1,"packages":{}}`)

	results, err := DiscoverInRoot(root)
	if err != nil {
		t.Fatalf("discover returned error for v1 lockfile: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 lockfiles for v1 package-lock, got %d: %+v", len(results), results)
	}
}

// Small helper struct to keep test assertions readable.
type deptreeMeta struct {
	Format    string
	Ecosystem string
	SHA256    string
	Count     int
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
