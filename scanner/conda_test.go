package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCondaMeta writes a conda-meta/<name>-<version>-py311.json manifest.
func writeCondaMeta(t *testing.T, condaMeta, name, version string) {
	t.Helper()
	data, _ := json.Marshal(map[string]string{"name": name, "version": version})
	path := filepath.Join(condaMeta, name+"-"+version+"-py311.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeDistInfo writes a site-packages/<name>-<version>.dist-info/METADATA,
// mimicking a `pip install` inside the env.
func writeDistInfo(t *testing.T, sitePackages, name, version string) {
	t.Helper()
	distInfo := filepath.Join(sitePackages, name+"-"+version+".dist-info")
	if err := os.MkdirAll(distInfo, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n"
	if err := os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCondaScanIncludesPipInstalledPackages is the P0-3 acceptance test:
// a conda env with conda-meta/numpy-*.json plus a pip-installed
// requests-2.19.0.dist-info in site-packages must yield both records.
func TestCondaScanIncludesPipInstalledPackages(t *testing.T) {
	env := t.TempDir()

	condaMeta := filepath.Join(env, "conda-meta")
	if err := os.MkdirAll(condaMeta, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCondaMeta(t, condaMeta, "numpy", "1.26.2")
	writeCondaMeta(t, condaMeta, "python", "3.11.7")

	site := filepath.Join(env, "lib", "python3.11", "site-packages")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDistInfo(t, site, "requests", "2.19.0")

	pkgs, errs := condaScanner{}.Scan(context.Background(), Environment{EnvType: EnvConda, Path: env})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	byName := make(map[string]PackageRecord, len(pkgs))
	for _, p := range pkgs {
		byName[p.Name] = p
		// Every emitted record stays tagged conda, even pip-origin ones.
		if p.EnvType != EnvConda {
			t.Errorf("package %s has EnvType %q, want %q", p.Name, p.EnvType, EnvConda)
		}
	}

	if _, ok := byName["numpy"]; !ok {
		t.Error("expected numpy record from conda-meta")
	}
	req, ok := byName["requests"]
	if !ok {
		t.Fatal("expected requests record from pip site-packages")
	}
	if req.Version != "2.19.0" {
		t.Errorf("requests version = %q, want 2.19.0", req.Version)
	}
	// Pip-origin marker: InstallPath points into site-packages (the pip
	// parser's .dist-info dir), not conda-meta — how the server distinguishes
	// origin without a new contract field.
	if !strings.Contains(filepath.ToSlash(req.InstallPath), "site-packages") {
		t.Errorf("requests InstallPath = %q, want a site-packages path", req.InstallPath)
	}
}

// TestCondaScanDedupPrefersCondaMeta verifies a package present in both
// conda-meta and pip site-packages with the SAME version appears once (a true
// duplicate is collapsed to the conda-meta record), matching across PEP 503
// name spelling differences.
func TestCondaScanDedupPrefersCondaMeta(t *testing.T) {
	env := t.TempDir()

	condaMeta := filepath.Join(env, "conda-meta")
	if err := os.MkdirAll(condaMeta, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCondaMeta(t, condaMeta, "PyYAML", "6.0") // conda-meta spelling + version

	site := filepath.Join(env, "lib", "python3.11", "site-packages")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDistInfo(t, site, "pyyaml", "6.0") // pip spelling, SAME PEP 503 name + version

	pkgs, errs := condaScanner{}.Scan(context.Background(), Environment{Path: env})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	var matches []PackageRecord
	for _, p := range pkgs {
		if normalizePEP503(p.Name) == "pyyaml" {
			matches = append(matches, p)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 pyyaml record, got %d: %+v", len(matches), matches)
	}
	if matches[0].Version != "6.0" {
		t.Errorf("deduped version = %q, want conda-meta 6.0", matches[0].Version)
	}
}

// TestCondaScanEmitsBothOnVersionDivergence verifies that when conda-meta and
// the env's pip site-packages disagree on the version of the same PEP 503
// package (the `pip install -U` inside an activated conda env case, or the
// reverse orphaned-.dist-info case), BOTH records are emitted so CVE
// correlation covers whichever version is actually on disk. The two records
// are distinguishable by InstallPath (conda-meta json vs site-packages
// .dist-info), so no information is lost.
func TestCondaScanEmitsBothOnVersionDivergence(t *testing.T) {
	env := t.TempDir()

	condaMeta := filepath.Join(env, "conda-meta")
	if err := os.MkdirAll(condaMeta, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCondaMeta(t, condaMeta, "PyYAML", "6.0") // stale conda-meta

	site := filepath.Join(env, "lib", "python3.11", "site-packages")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDistInfo(t, site, "pyyaml", "5.4.1") // on-disk .dist-info, different version

	pkgs, errs := condaScanner{}.Scan(context.Background(), Environment{Path: env})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	versions := make(map[string]PackageRecord)
	for _, p := range pkgs {
		if normalizePEP503(p.Name) == "pyyaml" {
			versions[p.Version] = p
		}
	}
	if len(versions) != 2 {
		t.Fatalf("expected both pyyaml versions emitted, got %d: %+v", len(versions), pkgs)
	}
	if _, ok := versions["6.0"]; !ok {
		t.Errorf("missing conda-meta version 6.0; got versions %v", recordVersionKeys(versions))
	}
	pip, ok := versions["5.4.1"]
	if !ok {
		t.Fatalf("missing on-disk pip version 5.4.1; got versions %v", recordVersionKeys(versions))
	}
	// The pip record must carry the site-packages InstallPath so the server can
	// tell the two origins apart without a new contract field.
	if !strings.Contains(filepath.ToSlash(pip.InstallPath), "site-packages") {
		t.Errorf("pip record InstallPath = %q, want a site-packages path", pip.InstallPath)
	}
}

func recordVersionKeys(m map[string]PackageRecord) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestCondaScanNoSitePackagesNoError verifies a Python-less conda env (no
// site-packages) does not emit a spurious "site-packages not found" error.
func TestCondaScanNoSitePackagesNoError(t *testing.T) {
	env := t.TempDir()
	condaMeta := filepath.Join(env, "conda-meta")
	if err := os.MkdirAll(condaMeta, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCondaMeta(t, condaMeta, "r-base", "4.3.1")

	pkgs, errs := condaScanner{}.Scan(context.Background(), Environment{Path: env})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
}

// TestGetCondaInterpreterVersionPrefixGuard covers the fix that stops
// sibling packages sharing the "python-" prefix (python-dateutil,
// python-json-logger) from being mistaken for the CPython interpreter
// record.  Only "python-<digit>…" qualifies.
func TestGetCondaInterpreterVersionPrefixGuard(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  string
	}{
		{
			name:  "only python-dateutil yields unknown",
			files: []string{"python-dateutil-2.8.2-py311.json", "numpy-1.26.0-py311.json"},
			want:  "unknown",
		},
		{
			name:  "python-json-logger not mistaken for interpreter",
			files: []string{"python-json-logger-2.0.7-py311.json"},
			want:  "unknown",
		},
		{
			name:  "real python-3.11.5 still detected",
			files: []string{"python-3.11.5-h955ad1f_0.json"},
			want:  "3.11.5",
		},
		{
			name:  "dateutil sibling does not shadow the real interpreter",
			files: []string{"python-dateutil-2.8.2-py311.json", "python-3.11.5-h955ad1f_0.json"},
			want:  "3.11.5",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte(`{}`), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := getCondaInterpreterVersion(dir, entries); got != tc.want {
				t.Errorf("getCondaInterpreterVersion = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizePEP503Conda(t *testing.T) {
	cases := map[string]string{
		"requests":     "requests",
		"PyYAML":       "pyyaml",
		"ruamel.yaml":  "ruamel-yaml",
		"ruamel_yaml":  "ruamel-yaml",
		"Foo__Bar.._x": "foo-bar-x",
	}
	for in, want := range cases {
		if got := normalizePEP503(in); got != want {
			t.Errorf("normalizePEP503(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCondaSupplierInheritedFromPipDistInfo proves an equal-version pip
// duplicate donates its supplier to the winning conda-meta record, which
// carries none of its own (SBOM-completeness v2 §4.2 — conda is a pypi source).
func TestCondaSupplierInheritedFromPipDistInfo(t *testing.T) {
	env := t.TempDir()
	condaMeta := filepath.Join(env, "conda-meta")
	if err := os.MkdirAll(condaMeta, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCondaMeta(t, condaMeta, "numpy", "1.26.2")

	site := filepath.Join(env, "lib", "python3.11", "site-packages")
	distInfo := filepath.Join(site, "numpy-1.26.2.dist-info")
	if err := os.MkdirAll(distInfo, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := "Metadata-Version: 2.1\nName: numpy\nVersion: 1.26.2\nAuthor: NumPy Developers\n"
	if err := os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, errs := condaScanner{}.Scan(context.Background(), Environment{EnvType: EnvConda, Path: env})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	var numpy *PackageRecord
	var count int
	for i := range pkgs {
		if pkgs[i].Name == "numpy" {
			numpy = &pkgs[i]
			count++
		}
	}
	if numpy == nil {
		t.Fatal("numpy not emitted")
	}
	if count != 1 {
		t.Fatalf("numpy emitted %d times, want 1 (equal-version duplicate collapses)", count)
	}
	// The winning conda-meta record (its InstallPath is conda-meta, not
	// site-packages) inherited the pip .dist-info supplier.
	if numpy.Supplier != "NumPy Developers" {
		t.Errorf("supplier = %q, want %q (inherited from pip dist-info)", numpy.Supplier, "NumPy Developers")
	}
}
