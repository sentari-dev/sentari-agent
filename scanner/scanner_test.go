package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestPackageRecordFields(t *testing.T) {
	pkg := PackageRecord{
		Name:        "requests",
		Version:     "2.31.0",
		InstallPath: "/usr/lib/python3/dist-packages/requests-2.31.0.dist-info",
		EnvType:     EnvPip,
		Environment: "/usr/lib/python3",
	}

	if pkg.Name != "requests" {
		t.Errorf("expected Name 'requests', got '%s'", pkg.Name)
	}
	if pkg.Version != "2.31.0" {
		t.Errorf("expected Version '2.31.0', got '%s'", pkg.Version)
	}
	if pkg.EnvType != EnvPip {
		t.Errorf("expected EnvType '%s', got '%s'", EnvPip, pkg.EnvType)
	}
}

func TestPackageRecordJSON(t *testing.T) {
	pkg := PackageRecord{
		Name:    "flask",
		Version: "3.0.0",
		EnvType: EnvVenv,
	}
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify omitempty: install_path should be absent when empty.
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	if _, ok := m["install_path"]; ok {
		t.Error("install_path should be omitted when empty")
	}
	if _, ok := m["interpreter_version"]; ok {
		t.Error("interpreter_version should be omitted when empty")
	}
	// Required fields should always be present.
	if _, ok := m["name"]; !ok {
		t.Error("name should always be present")
	}
	if _, ok := m["env_type"]; !ok {
		t.Error("env_type should always be present")
	}
}

func TestParseDistInfoMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	distInfo := filepath.Join(tmpDir, "requests-2.31.0.dist-info")
	if err := os.Mkdir(distInfo, 0755); err != nil {
		t.Fatal(err)
	}

	metadata := "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nSummary: HTTP library\n"
	if err := os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(metadata), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := parseDistInfo(distInfo, tmpDir)
	if err != nil {
		t.Fatalf("parseDistInfo failed: %v", err)
	}

	if pkg.Name != "requests" {
		t.Errorf("expected Name 'requests', got '%s'", pkg.Name)
	}
	if pkg.Version != "2.31.0" {
		t.Errorf("expected Version '2.31.0', got '%s'", pkg.Version)
	}
}

func TestParseDistInfoFallbackName(t *testing.T) {
	// When METADATA has no Name: header, fall back to directory name.
	tmpDir := t.TempDir()
	distInfo := filepath.Join(tmpDir, "wheel-0.41.3.dist-info")
	os.Mkdir(distInfo, 0755)
	os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte("Metadata-Version: 2.1\nVersion: 0.41.3\n"), 0644)

	pkg, err := parseDistInfo(distInfo, tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Name != "wheel" {
		// The fallback splits on last '-', so name = everything before last '-'.
		t.Errorf("Name fallback: expected 'wheel', got '%s'", pkg.Name)
	}
	if pkg.Version != "0.41.3" {
		t.Errorf("Version fallback: expected '0.41.3', got '%s'", pkg.Version)
	}
}

func TestParseEggInfoMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	eggInfo := filepath.Join(tmpDir, "setuptools-69.0.0.egg-info")
	if err := os.Mkdir(eggInfo, 0755); err != nil {
		t.Fatal(err)
	}

	pkgInfo := "Metadata-Version: 2.1\nName: setuptools\nVersion: 69.0.0\n"
	if err := os.WriteFile(filepath.Join(eggInfo, "PKG-INFO"), []byte(pkgInfo), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := parseEggInfo(eggInfo, tmpDir)
	if err != nil {
		t.Fatalf("parseEggInfo failed: %v", err)
	}

	if pkg.Name != "setuptools" {
		t.Errorf("expected Name 'setuptools', got '%s'", pkg.Name)
	}
	if pkg.Version != "69.0.0" {
		t.Errorf("expected Version '69.0.0', got '%s'", pkg.Version)
	}
}

func TestScannerEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		ScanRoot:   tmpDir,
		MaxDepth:   4,
		MaxWorkers: 2,
	}

	s := NewScanner(cfg)
	result, err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Packages) != 0 {
		t.Errorf("expected 0 packages, got %d", len(result.Packages))
	}
	if result.DeviceID == "" {
		t.Error("expected non-empty DeviceID")
	}
	if result.OS == "" {
		t.Error("expected non-empty OS")
	}
}

func TestScannerContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		ScanRoot:   tmpDir,
		MaxDepth:   4,
		MaxWorkers: 2,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	s := NewScanner(cfg)
	result, err := s.Run(ctx)
	if err != nil {
		t.Fatalf("scan should not return error on cancelled context: %v", err)
	}

	// With a cancelled context, discovery should bail early.
	if result == nil {
		t.Fatal("expected non-nil result even on cancellation")
	}
}

func TestScannerBrokenEnvironment(t *testing.T) {
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, "broken-venv")
	os.Mkdir(venvDir, 0755)
	os.WriteFile(filepath.Join(venvDir, "pyvenv.cfg"), []byte("home = /usr/bin\n"), 0644)

	cfg := Config{
		ScanRoot:   tmpDir,
		MaxDepth:   4,
		MaxWorkers: 2,
	}

	s := NewScanner(cfg)
	result, err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("scan should not fail on broken env: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// A broken venv should produce errors, not a crash.
	if len(result.Errors) == 0 {
		t.Log("No errors from broken venv — scan may have treated it as empty (acceptable)")
	}
}

func TestScannerDotVenvNotSkipped(t *testing.T) {
	// Ensure .venv directories are NOT skipped (they are valid venvs).
	tmpDir := t.TempDir()
	venvDir := filepath.Join(tmpDir, ".venv")
	os.Mkdir(venvDir, 0755)
	os.WriteFile(filepath.Join(venvDir, "pyvenv.cfg"), []byte("home = /usr/bin\n"), 0644)

	cfg := Config{
		ScanRoot:   tmpDir,
		MaxDepth:   4,
		MaxWorkers: 2,
	}

	s := NewScanner(cfg)
	envs, _ := s.discoverEnvironments(context.Background())

	found := false
	for _, env := range envs {
		if env.EnvType == EnvVenv && filepath.Base(env.Path) == ".venv" {
			found = true
			break
		}
	}
	if !found {
		t.Error(".venv directory was not discovered as a venv environment")
	}
}

func TestScannerSkipDirs(t *testing.T) {
	// Ensure .git and __pycache__ are skipped unconditionally —
	// no plugin has a legitimate reason to see them.  node_modules
	// is intentionally NOT in this test any more: Sprint-17's npm
	// plugin claims it as a scan root (returns Matched+Terminal
	// on Match), so the walker DOES visit node_modules now.  A
	// pathological pyvenv.cfg planted there surfaces as a venv
	// env, but that matches reality.  Separate test below covers
	// the npm-claims-node_modules case explicitly.
	tmpDir := t.TempDir()
	for _, skip := range []string{".git", "__pycache__"} {
		dir := filepath.Join(tmpDir, skip)
		os.Mkdir(dir, 0755)
		// Place a pyvenv.cfg inside — should NOT be discovered.
		os.WriteFile(filepath.Join(dir, "pyvenv.cfg"), []byte("home = /usr/bin\n"), 0644)
	}

	cfg := Config{
		ScanRoot:   tmpDir,
		MaxDepth:   4,
		MaxWorkers: 2,
	}

	s := NewScanner(cfg)
	envs, _ := s.discoverEnvironments(context.Background())
	if len(envs) != 0 {
		t.Errorf("expected 0 discovered envs in skip dirs, got %d", len(envs))
	}
}

func TestScannerVenvDiscovery(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a venv with pyvenv.cfg.
	venvDir := filepath.Join(tmpDir, "myenv")
	os.Mkdir(venvDir, 0755)
	os.WriteFile(filepath.Join(venvDir, "pyvenv.cfg"), []byte("home = /usr/bin\nversion = 3.11.0\n"), 0644)

	// Create a conda env with conda-meta.
	condaDir := filepath.Join(tmpDir, "miniconda")
	os.MkdirAll(filepath.Join(condaDir, "conda-meta"), 0755)

	// Create a poetry project with poetry.lock.
	poetryDir := filepath.Join(tmpDir, "myproject")
	os.Mkdir(poetryDir, 0755)
	os.WriteFile(filepath.Join(poetryDir, "poetry.lock"), []byte("[[package]]\nname = \"test\"\n"), 0644)

	cfg := Config{
		ScanRoot:   tmpDir,
		MaxDepth:   4,
		MaxWorkers: 2,
	}

	s := NewScanner(cfg)
	envs, errs := s.discoverEnvironments(context.Background())

	if len(errs) != 0 {
		t.Logf("discovery errors: %v", errs)
	}

	types := make(map[EnvType]bool)
	for _, env := range envs {
		types[env.EnvType] = true
	}

	if !types[EnvVenv] {
		t.Error("expected to discover a venv environment")
	}
	if !types[EnvConda] {
		t.Error("expected to discover a conda environment")
	}
	if !types[EnvPoetry] {
		t.Error("expected to discover a poetry environment")
	}
}

func TestNewScannerDefaults(t *testing.T) {
	s := NewScanner(Config{})
	if s.cfg.MaxDepth != 12 {
		t.Errorf("expected MaxDepth=12, got %d", s.cfg.MaxDepth)
	}
	if s.cfg.MaxWorkers != 8 {
		t.Errorf("expected MaxWorkers=8, got %d", s.cfg.MaxWorkers)
	}
	if s.cfg.ScanRoot == "" {
		t.Error("expected non-empty ScanRoot default")
	}
}

func TestIsPythonPackage(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"python3", true},
		{"python3-pip", true},
		{"python3-numpy", true},
		{"libpython3.11", true},
		{"nginx", false},
		{"curl", false},
		{"pip", true},
		{"pypy3", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPythonPackage(tt.name)
			if got != tt.expected {
				t.Errorf("isPythonPackage(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

// --- Poetry parser tests ---

func TestParseTomlKeyValue(t *testing.T) {
	tests := []struct {
		line      string
		wantKey   string
		wantValue string
		wantOK    bool
	}{
		{`name = "requests"`, "name", "requests", true},
		{`version = "2.31.0"`, "version", "2.31.0", true},
		{`description = "HTTP library"`, "description", "HTTP library", true},
		{`python-versions = ">=3.7"`, "python-versions", ">=3.7", true},
		{`optional = false`, "", "", false}, // boolean, not a string
		{`# comment line`, "", "", false},
		{``, "", "", false},
		{`[[package]]`, "", "", false}, // section header
		{`name="no-spaces"`, "name", "no-spaces", true},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			key, value, ok := parseTomlKeyValue(tt.line)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if key != tt.wantKey {
				t.Errorf("key = %q, want %q", key, tt.wantKey)
			}
			if value != tt.wantValue {
				t.Errorf("value = %q, want %q", value, tt.wantValue)
			}
		})
	}
}

func TestScanPoetryEnvironment(t *testing.T) {
	tmpDir := t.TempDir()

	poetryLock := `[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"

[[package]]
name = "urllib3"
version = "2.1.0"
description = "HTTP library with thread-safe connection pooling"
optional = false
python-versions = ">=3.8"

[[package]]
name = "certifi"
version = "2023.11.17"
description = "Python package for providing Mozilla's CA Bundle."
optional = false
python-versions = ">=3.6"

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "abc123"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "poetry.lock"), []byte(poetryLock), 0644); err != nil {
		t.Fatal(err)
	}

	packages, errors := scanPoetryEnvironment(tmpDir)
	if len(errors) != 0 {
		t.Errorf("unexpected errors: %v", errors)
	}
	if len(packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(packages))
	}

	// Verify first package.
	if packages[0].Name != "requests" {
		t.Errorf("expected first package 'requests', got '%s'", packages[0].Name)
	}
	if packages[0].Version != "2.31.0" {
		t.Errorf("expected version '2.31.0', got '%s'", packages[0].Version)
	}
	if packages[0].EnvType != EnvPoetry {
		t.Errorf("expected EnvType '%s', got '%s'", EnvPoetry, packages[0].EnvType)
	}

	// Verify all packages have environment set.
	for i, pkg := range packages {
		if pkg.Environment != tmpDir {
			t.Errorf("package %d: expected Environment '%s', got '%s'", i, tmpDir, pkg.Environment)
		}
	}
}

func TestScanPoetryMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	packages, errors := scanPoetryEnvironment(tmpDir)
	if len(packages) != 0 {
		t.Error("expected 0 packages for missing poetry.lock")
	}
	if len(errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(errors))
	}
}

// --- Conda parser tests ---

func TestScanCondaEnvironment(t *testing.T) {
	tmpDir := t.TempDir()
	condaMeta := filepath.Join(tmpDir, "conda-meta")
	os.Mkdir(condaMeta, 0755)

	// Write a couple of conda package metadata JSON files.
	for _, pkg := range []struct{ name, version string }{
		{"numpy", "1.26.2"},
		{"pandas", "2.1.4"},
	} {
		data, _ := json.Marshal(map[string]string{
			"name":    pkg.name,
			"version": pkg.version,
		})
		os.WriteFile(filepath.Join(condaMeta, fmt.Sprintf("%s-%s-py311.json", pkg.name, pkg.version)), data, 0644)
	}

	packages, errors := scanCondaEnvironment(tmpDir)
	if len(errors) != 0 {
		t.Errorf("unexpected errors: %v", errors)
	}
	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}
}

// --- Pipenv parser tests ---

func TestScanPipenvEnvironment(t *testing.T) {
	tmpDir := t.TempDir()

	pipfileLock := `{
    "_meta": {"requires": {"python_version": "3.11"}},
    "default": {
        "flask": {"version": "==3.0.0"},
        "werkzeug": {"version": "==3.0.1"}
    },
    "develop": {
        "pytest": {"version": "==7.4.3"}
    }
}`
	os.WriteFile(filepath.Join(tmpDir, "Pipfile.lock"), []byte(pipfileLock), 0644)

	packages, errors := scanPipenvEnvironment(tmpDir)
	if len(errors) != 0 {
		t.Errorf("unexpected errors: %v", errors)
	}
	if len(packages) != 3 {
		t.Fatalf("expected 3 packages (2 default + 1 develop), got %d", len(packages))
	}

	// Check version stripping of == prefix.
	for _, pkg := range packages {
		if pkg.Version == "" {
			t.Errorf("package %s has empty version", pkg.Name)
		}
		if pkg.Version[0] == '=' {
			t.Errorf("package %s version still has == prefix: %s", pkg.Name, pkg.Version)
		}
	}
}

// --- Benchmark: simulate scanning many packages ---

func BenchmarkParseDistInfo(b *testing.B) {
	tmpDir := b.TempDir()
	distInfo := filepath.Join(tmpDir, "bench-pkg-1.0.0.dist-info")
	os.Mkdir(distInfo, 0755)
	os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte("Metadata-Version: 2.1\nName: bench-pkg\nVersion: 1.0.0\nSummary: A benchmark package\nAuthor: Test\nLicense: MIT\n"), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseDistInfo(distInfo, tmpDir)
	}
}

func BenchmarkScanPoetryEnvironment(b *testing.B) {
	tmpDir := b.TempDir()

	// Generate a poetry.lock with 200 packages.
	var content string
	for i := 0; i < 200; i++ {
		content += fmt.Sprintf("[[package]]\nname = \"pkg-%d\"\nversion = \"%d.0.0\"\ndescription = \"Package %d\"\noptional = false\n\n", i, i, i)
	}
	content += "[metadata]\nlock-version = \"2.0\"\n"
	os.WriteFile(filepath.Join(tmpDir, "poetry.lock"), []byte(content), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanPoetryEnvironment(tmpDir)
	}
}

func BenchmarkScanFullWithManyEnvironments(b *testing.B) {
	// Create a directory tree with multiple venvs, each containing dist-info packages.
	rootDir := b.TempDir()

	for v := 0; v < 10; v++ {
		venvDir := filepath.Join(rootDir, fmt.Sprintf("project-%d", v), ".venv")
		siteDir := filepath.Join(venvDir, "lib", "python3.11", "site-packages")
		os.MkdirAll(siteDir, 0755)
		os.WriteFile(filepath.Join(venvDir, "pyvenv.cfg"), []byte("home = /usr/bin\nversion = 3.11.0\n"), 0644)

		// Each venv has 100 packages.
		for p := 0; p < 100; p++ {
			distDir := filepath.Join(siteDir, fmt.Sprintf("pkg%d-%d.0.0.dist-info", p, p))
			os.Mkdir(distDir, 0755)
			metadata := fmt.Sprintf("Metadata-Version: 2.1\nName: pkg%d\nVersion: %d.0.0\n", p, p)
			os.WriteFile(filepath.Join(distDir, "METADATA"), []byte(metadata), 0644)
		}
	}

	cfg := Config{
		ScanRoot:   rootDir,
		MaxDepth:   8,
		MaxWorkers: 8,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewScanner(cfg)
		result, err := s.Run(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Packages) == 0 {
			b.Fatal("expected packages")
		}
	}
}

func BenchmarkDiscoverEnvironments(b *testing.B) {
	rootDir := b.TempDir()

	// Create a moderately deep directory tree with varied envs.
	for i := 0; i < 50; i++ {
		dir := filepath.Join(rootDir, fmt.Sprintf("project-%d", i))
		os.Mkdir(dir, 0755)

		if i%3 == 0 {
			// venv
			os.WriteFile(filepath.Join(dir, "pyvenv.cfg"), []byte("home = /usr/bin\n"), 0644)
		} else if i%3 == 1 {
			// poetry
			os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte("[[package]]\n"), 0644)
		} else {
			// pipenv
			os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(`{"default":{},"develop":{}}`), 0644)
		}
	}

	cfg := Config{
		ScanRoot:   rootDir,
		MaxDepth:   8,
		MaxWorkers: 8,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewScanner(cfg)
		envs, _ := s.discoverEnvironments(context.Background())
		_ = envs
	}
}

func TestScanResultTimestamps(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		ScanRoot:   tmpDir,
		MaxDepth:   4,
		MaxWorkers: 2,
	}

	before := time.Now().UTC()
	s := NewScanner(cfg)
	result, _ := s.Run(context.Background())
	after := time.Now().UTC()

	if result.ScannedAt.Before(before) || result.ScannedAt.After(after) {
		t.Errorf("ScannedAt %v not between %v and %v", result.ScannedAt, before, after)
	}
	if result.AgentVersion == "" {
		t.Error("expected non-empty AgentVersion")
	}
}

// ---------------------------------------------------------------------------
// RPM header parser
// ---------------------------------------------------------------------------

// buildRPMBlob constructs a minimal valid rpmdb blob with the given version
// and release strings, matching the format stored in Packages.blob.
func buildRPMBlob(version, release string) []byte {
	const (
		typeString    = uint32(6)
		tagVersion    = uint32(1001)
		tagRelease    = uint32(1002)
		headerOffset  = 8
		entrySize     = 16
	)

	// Data store: version\0release\0
	store := append([]byte(version), 0)
	releaseOffset := uint32(len(store))
	store = append(store, []byte(release)...)
	store = append(store, 0)

	nindex := uint32(2)
	hsize := uint32(len(store))

	buf := make([]byte, headerOffset+int(nindex)*entrySize+len(store))

	// Header
	buf[0], buf[1], buf[2], buf[3] = byte(nindex>>24), byte(nindex>>16), byte(nindex>>8), byte(nindex)
	buf[4], buf[5], buf[6], buf[7] = byte(hsize>>24), byte(hsize>>16), byte(hsize>>8), byte(hsize)

	writeEntry := func(pos int, tag, typ, offset, count uint32) {
		buf[pos+0] = byte(tag >> 24); buf[pos+1] = byte(tag >> 16); buf[pos+2] = byte(tag >> 8); buf[pos+3] = byte(tag)
		buf[pos+4] = byte(typ >> 24); buf[pos+5] = byte(typ >> 16); buf[pos+6] = byte(typ >> 8); buf[pos+7] = byte(typ)
		buf[pos+8] = byte(offset >> 24); buf[pos+9] = byte(offset >> 16); buf[pos+10] = byte(offset >> 8); buf[pos+11] = byte(offset)
		buf[pos+12] = byte(count >> 24); buf[pos+13] = byte(count >> 16); buf[pos+14] = byte(count >> 8); buf[pos+15] = byte(count)
	}

	writeEntry(headerOffset, tagVersion, typeString, 0, 1)
	writeEntry(headerOffset+entrySize, tagRelease, typeString, releaseOffset, 1)

	copy(buf[headerOffset+int(nindex)*entrySize:], store)
	return buf
}

func TestParseRPMHeaderVersion(t *testing.T) {
	tests := []struct {
		name     string
		blob     []byte
		expected string
	}{
		{
			name:     "version and release",
			blob:     buildRPMBlob("3.12.0", "1.el9"),
			expected: "3.12.0-1.el9",
		},
		{
			name:     "version only (empty release)",
			blob:     buildRPMBlob("2.7.18", ""),
			expected: "2.7.18",
		},
		{
			name:     "empty blob returns empty string",
			blob:     []byte{},
			expected: "",
		},
		{
			name:     "too-short blob returns empty string",
			blob:     []byte{0x00, 0x01},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRPMHeaderVersion(tc.blob)
			if got != tc.expected {
				t.Errorf("parseRPMHeaderVersion() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestDiscoverWindowsRegistryEnvsNoOp(t *testing.T) {
	// On non-Windows platforms the registry scanner must return (nil, nil)
	// without panicking.  On Windows this will exercise the real registry
	// lookup and may return real envs — the invariant we care about is
	// that DiscoverAll doesn't crash on an unsupported OS.
	envs, errs := windowsRegistryScanner{}.DiscoverAll(context.Background())
	if runtime.GOOS != "windows" {
		if len(envs) != 0 || len(errs) != 0 {
			t.Errorf("expected empty result on non-Windows, got %d envs %d errs", len(envs), len(errs))
		}
	}
}

func TestVenvScannerScanTagsPackagesAsEnvVenv(t *testing.T) {
	// After the plugin-registry refactor, venv scanning goes through
	// venvScanner.Scan — which must tag every produced package as EnvVenv
	// even though the underlying parser (scanPipEnvironment) defaults to
	// EnvPip.
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "pyvenv.cfg"), []byte("home = /usr/bin\nversion = 3.11.0\n"), 0644)
	sitePkgs := filepath.Join(tmpDir, "lib", "python3.11", "site-packages")
	os.MkdirAll(sitePkgs, 0755)
	distInfo := filepath.Join(sitePkgs, "mypkg-1.0.0.dist-info")
	os.MkdirAll(distInfo, 0755)
	os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte("Metadata-Version: 2.1\nName: mypkg\nVersion: 1.0.0\n"), 0644)

	pkgs, _ := venvScanner{}.Scan(context.Background(), Environment{
		EnvType: EnvVenv,
		Path:    tmpDir,
		Name:    "testvenv",
	})
	if len(pkgs) == 0 {
		t.Fatal("expected at least one package from venv scan")
	}
	for _, pkg := range pkgs {
		if pkg.EnvType != EnvVenv {
			t.Errorf("expected EnvType=%q, got %q for package %s", EnvVenv, pkg.EnvType, pkg.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests for isVenvDangling
// ---------------------------------------------------------------------------

func TestIsVenvDangling_HealthyVenv(t *testing.T) {
	// A venv whose home dir exists and has no bin/python → should NOT be
	// flagged as dangling.
	tmpDir := t.TempDir()
	cfg := filepath.Join(tmpDir, "pyvenv.cfg")
	os.WriteFile(cfg, []byte("home = /usr/bin\nversion = 3.11.0\n"), 0644)

	reason := isVenvDangling(tmpDir, cfg)
	if reason != "" {
		t.Errorf("expected healthy venv, got: %s", reason)
	}
}

func TestIsVenvDangling_HomeMissing(t *testing.T) {
	// pyvenv.cfg points to a directory that no longer exists.
	tmpDir := t.TempDir()
	cfg := filepath.Join(tmpDir, "pyvenv.cfg")
	os.WriteFile(cfg, []byte("home = /nonexistent/python311/bin\nversion = 3.11.0\n"), 0644)

	reason := isVenvDangling(tmpDir, cfg)
	if reason == "" {
		t.Fatal("expected dangling venv due to missing home dir, got empty string")
	}
	if !contains(reason, "base Python directory") {
		t.Errorf("expected reason to mention 'base Python directory', got: %s", reason)
	}
}

func TestIsVenvDangling_SymlinkBroken(t *testing.T) {
	// bin/python is a symlink to a target that doesn't exist.
	tmpDir := t.TempDir()
	cfg := filepath.Join(tmpDir, "pyvenv.cfg")
	// home points to an existing dir so check 1 passes — only check 2 triggers.
	os.WriteFile(cfg, []byte("home = /usr/bin\nversion = 3.11.0\n"), 0644)

	binDir := filepath.Join(tmpDir, "bin")
	os.MkdirAll(binDir, 0755)
	pythonBin := filepath.Join(binDir, "python")
	os.Symlink("/nonexistent/python3.11", pythonBin) // dangling symlink

	reason := isVenvDangling(tmpDir, cfg)
	if reason == "" {
		t.Fatal("expected dangling venv due to broken symlink, got empty string")
	}
	if !contains(reason, "python symlink") {
		t.Errorf("expected reason to mention 'python symlink', got: %s", reason)
	}
}

func TestIsVenvDangling_SymlinkHealthy(t *testing.T) {
	// bin/python is a symlink to a real binary — should NOT be flagged.
	tmpDir := t.TempDir()
	cfg := filepath.Join(tmpDir, "pyvenv.cfg")
	os.WriteFile(cfg, []byte("home = /usr/bin\nversion = 3.11.0\n"), 0644)

	binDir := filepath.Join(tmpDir, "bin")
	os.MkdirAll(binDir, 0755)
	pythonBin := filepath.Join(binDir, "python")
	// Point to a real file — use the pyvenv.cfg itself as a convenient target.
	os.Symlink(cfg, pythonBin)

	reason := isVenvDangling(tmpDir, cfg)
	if reason != "" {
		t.Errorf("expected healthy venv with valid symlink, got: %s", reason)
	}
}

func TestDiscoverSkipsDanglingVenv(t *testing.T) {
	// A dangling venv should NOT appear in discovered envs but SHOULD
	// appear in errors.
	tmpDir := t.TempDir()

	// Create a dangling venv (home dir doesn't exist).
	danglingVenv := filepath.Join(tmpDir, "broken-venv")
	os.MkdirAll(danglingVenv, 0755)
	os.WriteFile(filepath.Join(danglingVenv, "pyvenv.cfg"),
		[]byte("home = /nonexistent/python/bin\nversion = 3.11.0\n"), 0644)

	// Create a healthy venv alongside it.
	healthyVenv := filepath.Join(tmpDir, "good-venv")
	os.MkdirAll(healthyVenv, 0755)
	os.WriteFile(filepath.Join(healthyVenv, "pyvenv.cfg"),
		[]byte("home = /usr/bin\nversion = 3.13.0\n"), 0644)

	cfg := Config{ScanRoot: tmpDir, MaxDepth: 4, MaxWorkers: 1}
	s := NewScanner(cfg)
	envs, errs := s.discoverEnvironments(context.Background())

	// The healthy venv must be discovered.
	found := false
	for _, e := range envs {
		if e.Path == healthyVenv {
			found = true
		}
		if e.Path == danglingVenv {
			t.Error("dangling venv should NOT be in discovered environments")
		}
	}
	if !found {
		t.Error("expected healthy venv to be discovered")
	}

	// There should be an error entry for the dangling venv.
	foundErr := false
	for _, e := range errs {
		if e.Path == danglingVenv {
			foundErr = true
		}
	}
	if !foundErr {
		t.Error("expected a ScanError for the dangling venv")
	}
}

// helper — strings.Contains with clearer test output intent.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDefaultMaxDepthIs12(t *testing.T) {
	s := NewScanner(Config{})
	if s.cfg.MaxDepth != 12 {
		t.Errorf("expected default MaxDepth=12, got %d", s.cfg.MaxDepth)
	}
}

func TestParseEggLink(t *testing.T) {
	sitePackages := t.TempDir()
	srcDir := filepath.Join(t.TempDir(), "my-project")
	os.MkdirAll(srcDir, 0755)

	pkgInfo := "Metadata-Version: 1.0\nName: my-project\nVersion: 1.2.3\n"
	os.MkdirAll(filepath.Join(srcDir, "my_project.egg-info"), 0755)
	os.WriteFile(filepath.Join(srcDir, "my_project.egg-info", "PKG-INFO"), []byte(pkgInfo), 0644)

	eggLinkContent := srcDir + "\n.\n"
	os.WriteFile(filepath.Join(sitePackages, "my-project.egg-link"), []byte(eggLinkContent), 0644)

	pkg, err := parseEggLink(filepath.Join(sitePackages, "my-project.egg-link"), sitePackages)
	if err != nil {
		t.Fatalf("parseEggLink failed: %v", err)
	}
	if pkg.Name != "my-project" {
		t.Errorf("expected Name 'my-project', got %q", pkg.Name)
	}
	if pkg.Version != "1.2.3" {
		t.Errorf("expected Version '1.2.3', got %q", pkg.Version)
	}
}

func TestParseEggLinkNoPkgInfo(t *testing.T) {
	sitePackages := t.TempDir()
	srcDir := filepath.Join(t.TempDir(), "bare-project")
	os.MkdirAll(srcDir, 0755)

	eggLinkContent := srcDir + "\n"
	os.WriteFile(filepath.Join(sitePackages, "bare-project.egg-link"), []byte(eggLinkContent), 0644)

	pkg, err := parseEggLink(filepath.Join(sitePackages, "bare-project.egg-link"), sitePackages)
	if err != nil {
		t.Fatalf("parseEggLink failed: %v", err)
	}
	if pkg.Name != "bare-project" {
		t.Errorf("expected Name 'bare-project', got %q", pkg.Name)
	}
	if pkg.Version != "unknown" {
		t.Errorf("expected Version 'unknown', got %q", pkg.Version)
	}
}

func TestScanPipEnvironmentFindsEggLinks(t *testing.T) {
	envDir := t.TempDir()
	sitePackages := filepath.Join(envDir, "lib", "python3.12", "site-packages")
	os.MkdirAll(sitePackages, 0755)

	distInfo := filepath.Join(sitePackages, "requests-2.31.0.dist-info")
	os.MkdirAll(distInfo, 0755)
	os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte("Name: requests\nVersion: 2.31.0\n"), 0644)

	srcDir := filepath.Join(t.TempDir(), "my-lib")
	os.MkdirAll(filepath.Join(srcDir, "my_lib.egg-info"), 0755)
	os.WriteFile(
		filepath.Join(srcDir, "my_lib.egg-info", "PKG-INFO"),
		[]byte("Metadata-Version: 1.0\nName: my-lib\nVersion: 0.5.0\n"),
		0644,
	)
	os.WriteFile(
		filepath.Join(sitePackages, "my-lib.egg-link"),
		[]byte(srcDir+"\n.\n"),
		0644,
	)

	pkgs, errs := scanPipEnvironment(envDir)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	names := map[string]string{}
	for _, p := range pkgs {
		names[p.Name] = p.Version
	}
	if v, ok := names["requests"]; !ok || v != "2.31.0" {
		t.Errorf("expected requests@2.31.0, got %v", names)
	}
	if v, ok := names["my-lib"]; !ok || v != "0.5.0" {
		t.Errorf("expected my-lib@0.5.0, got %v", names)
	}
}

func TestExtraScanRootsPyenv(t *testing.T) {
	homeDir := t.TempDir()
	pyenvRoot := filepath.Join(homeDir, ".pyenv", "versions", "3.12.0")
	sitePackages := filepath.Join(pyenvRoot, "lib", "python3.12", "site-packages")
	os.MkdirAll(sitePackages, 0755)

	distInfo := filepath.Join(sitePackages, "numpy-1.26.0.dist-info")
	os.MkdirAll(distInfo, 0755)
	os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte("Name: numpy\nVersion: 1.26.0\n"), 0644)

	roots := extraScanRoots(homeDir)

	found := false
	for _, root := range roots {
		if root == filepath.Join(homeDir, ".pyenv", "versions") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected .pyenv/versions in extra roots, got %v", roots)
	}
}

func TestExtraScanRootsAsdf(t *testing.T) {
	homeDir := t.TempDir()
	asdfRoot := filepath.Join(homeDir, ".asdf", "installs", "python", "3.11.5")
	sitePackages := filepath.Join(asdfRoot, "lib", "python3.11", "site-packages")
	os.MkdirAll(sitePackages, 0755)

	roots := extraScanRoots(homeDir)

	found := false
	for _, root := range roots {
		if root == filepath.Join(homeDir, ".asdf", "installs", "python") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected .asdf/installs/python in extra roots, got %v", roots)
	}
}

func TestExtraScanRootsEmpty(t *testing.T) {
	homeDir := t.TempDir()

	roots := extraScanRoots(homeDir)
	if len(roots) != 0 {
		t.Errorf("expected no extra roots for empty home, got %v", roots)
	}
}

func TestScannerDiscoversPyenvEnvironments(t *testing.T) {
	scanRoot := t.TempDir()
	homeDir := filepath.Join(scanRoot, "home")
	pyenvVersions := filepath.Join(homeDir, ".pyenv", "versions", "3.12.0")
	sitePackages := filepath.Join(pyenvVersions, "lib", "python3.12", "site-packages")
	os.MkdirAll(sitePackages, 0755)

	distInfo := filepath.Join(sitePackages, "flask-3.0.0.dist-info")
	os.MkdirAll(distInfo, 0755)
	os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte("Name: flask\nVersion: 3.0.0\n"), 0644)

	// Scan with depth 3 — too shallow for the main walk to reach site-packages.
	// The extra roots mechanism should discover it anyway.
	s := NewScanner(Config{ScanRoot: scanRoot, MaxDepth: 3})
	result, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, pkg := range result.Packages {
		if pkg.Name == "flask" && pkg.Version == "3.0.0" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find flask@3.0.0 via pyenv extra root, got packages: %v", result.Packages)
	}
}
