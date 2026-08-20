package gobinaries

import (
	"runtime/debug"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

const binPath = "/usr/local/bin/tool"

// findRecord returns the first record with the given name, or false.
func findRecord(recs []recordish, name string) (recordish, bool) {
	for _, r := range recs {
		if r.name == name {
			return r, true
		}
	}
	return recordish{}, false
}

type recordish struct {
	name        string
	version     string
	envType     string
	installPath string
	environment string
}

func toRecordish(recs []scanner.PackageRecord) []recordish {
	out := make([]recordish, 0, len(recs))
	for _, r := range recs {
		out = append(out, recordish{
			name:        r.Name,
			version:     r.Version,
			envType:     r.EnvType,
			installPath: r.InstallPath,
			environment: r.Environment,
		})
	}
	return out
}

func TestRecordsFromBuildInfo_MainAndDeps(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.23.0",
		Path:      "github.com/acme/tool",
		Main:      debug.Module{Path: "github.com/acme/tool", Version: "v1.4.0"},
		Deps: []*debug.Module{
			{Path: "github.com/spf13/cobra", Version: "v1.8.0"},
			{Path: "github.com/spf13/pflag", Version: "v1.0.5"},
		},
	}
	recs, errs := recordsFromBuildInfo(bi, binPath)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	rv := toRecordish(recs)
	// main + 2 deps + 1 stdlib toolchain record
	if len(rv) != 4 {
		t.Fatalf("want 4 records (main+2deps+stdlib), got %d: %+v", len(rv), rv)
	}
	main, ok := findRecord(rv, "github.com/acme/tool")
	if !ok {
		t.Fatal("main module record missing")
	}
	if main.version != "v1.4.0" {
		t.Errorf("main version = %q, want v1.4.0", main.version)
	}
	for _, r := range rv {
		if r.envType != EnvGoBinary {
			t.Errorf("record %q env_type = %q, want %q", r.name, r.envType, EnvGoBinary)
		}
		if r.installPath != binPath || r.environment != binPath {
			t.Errorf("record %q install/env = %q/%q, want %q", r.name, r.installPath, r.environment, binPath)
		}
	}
	if _, ok := findRecord(rv, "github.com/spf13/cobra"); !ok {
		t.Error("cobra dep record missing")
	}
}

func TestRecordsFromBuildInfo_StdlibRecordCarriesGoVersion(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.23.4",
		Path:      "github.com/acme/tool",
		Main:      debug.Module{Path: "github.com/acme/tool", Version: "v1.0.0"},
	}
	recs, _ := recordsFromBuildInfo(bi, binPath)
	rv := toRecordish(recs)
	std, ok := findRecord(rv, "stdlib")
	if !ok {
		t.Fatal("stdlib record missing")
	}
	if std.version != "go1.23.4" {
		t.Errorf("stdlib version = %q, want go1.23.4 (GoVersion verbatim)", std.version)
	}
}

func TestRecordsFromBuildInfo_ReplaceDirectiveEmitsReplacement(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.23.0",
		Path:      "github.com/acme/tool",
		Main:      debug.Module{Path: "github.com/acme/tool", Version: "v1.0.0"},
		Deps: []*debug.Module{
			{
				Path:    "github.com/up/stream",
				Version: "v1.0.0",
				Replace: &debug.Module{Path: "github.com/fork/stream", Version: "v1.0.1"},
			},
		},
	}
	recs, _ := recordsFromBuildInfo(bi, binPath)
	rv := toRecordish(recs)
	if _, ok := findRecord(rv, "github.com/up/stream"); ok {
		t.Error("original (replaced) module must not be emitted")
	}
	repl, ok := findRecord(rv, "github.com/fork/stream")
	if !ok {
		t.Fatal("replacement module record missing")
	}
	if repl.version != "v1.0.1" {
		t.Errorf("replacement version = %q, want v1.0.1", repl.version)
	}
}

func TestRecordsFromBuildInfo_DevelMainUsesVcsRevision(t *testing.T) {
	rev := "0123456789abcdef0123456789abcdef01234567"
	bi := &debug.BuildInfo{
		GoVersion: "go1.23.0",
		Path:      "github.com/acme/tool",
		Main:      debug.Module{Path: "github.com/acme/tool", Version: "(devel)"},
		Settings:  []debug.BuildSetting{{Key: "vcs.revision", Value: rev}},
	}
	recs, _ := recordsFromBuildInfo(bi, binPath)
	rv := toRecordish(recs)
	main, ok := findRecord(rv, "github.com/acme/tool")
	if !ok {
		t.Fatal("main record missing")
	}
	if main.version != rev {
		t.Errorf("main version = %q, want vcs.revision %q", main.version, rev)
	}
}

func TestRecordsFromBuildInfo_DevelMainWithoutVcsKeepsDevel(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.23.0",
		Path:      "github.com/acme/tool",
		Main:      debug.Module{Path: "github.com/acme/tool", Version: "(devel)"},
	}
	recs, _ := recordsFromBuildInfo(bi, binPath)
	rv := toRecordish(recs)
	main, ok := findRecord(rv, "github.com/acme/tool")
	if !ok {
		t.Fatal("main record missing")
	}
	if main.version != "(devel)" {
		t.Errorf("main version = %q, want (devel) preserved", main.version)
	}
}

func TestRecordsFromBuildInfo_PseudoVersionVerbatim(t *testing.T) {
	pseudo := "v0.0.0-20240101120000-abcdef123456"
	bi := &debug.BuildInfo{
		GoVersion: "go1.23.0",
		Path:      "github.com/acme/tool",
		Main:      debug.Module{Path: "github.com/acme/tool", Version: "v1.0.0"},
		Deps:      []*debug.Module{{Path: "golang.org/x/sys", Version: pseudo}},
	}
	recs, _ := recordsFromBuildInfo(bi, binPath)
	rv := toRecordish(recs)
	dep, ok := findRecord(rv, "golang.org/x/sys")
	if !ok {
		t.Fatal("pseudo-version dep record missing")
	}
	if dep.version != pseudo {
		t.Errorf("dep version = %q, want pseudo-version verbatim %q", dep.version, pseudo)
	}
}

func TestRecordsFromBuildInfo_EmptyMainPathEmitsDepsOnly(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.23.0",
		Main:      debug.Module{Path: "", Version: ""},
		Deps:      []*debug.Module{{Path: "github.com/x/y", Version: "v1.0.0"}},
	}
	recs, _ := recordsFromBuildInfo(bi, binPath)
	rv := toRecordish(recs)
	if _, ok := findRecord(rv, ""); ok {
		t.Error("must not emit a record with an empty name")
	}
	if _, ok := findRecord(rv, "github.com/x/y"); !ok {
		t.Error("dep record should still be emitted")
	}
}

func TestRecordsFromBuildInfo_NoModuleInfoEmitsNothingButStdlib(t *testing.T) {
	// A binary with a GoVersion but no module path/deps still identifies the
	// toolchain; it must not panic or fabricate a module name.
	bi := &debug.BuildInfo{GoVersion: "go1.23.0"}
	recs, _ := recordsFromBuildInfo(bi, binPath)
	rv := toRecordish(recs)
	for _, r := range rv {
		if r.name == "" {
			t.Error("must not fabricate an empty-named record")
		}
	}
}

func TestRecordsFromBuildInfo_ModuleCapTruncates(t *testing.T) {
	orig := maxModulesPerBinary
	maxModulesPerBinary = 3
	defer func() { maxModulesPerBinary = orig }()

	deps := make([]*debug.Module, 0, 5)
	for i := 0; i < 5; i++ {
		deps = append(deps, &debug.Module{Path: "github.com/dep/n" + string(rune('a'+i)), Version: "v1.0.0"})
	}
	bi := &debug.BuildInfo{
		GoVersion: "go1.23.0",
		Path:      "github.com/acme/tool",
		Main:      debug.Module{Path: "github.com/acme/tool", Version: "v1.0.0"},
		Deps:      deps,
	}
	recs, errs := recordsFromBuildInfo(bi, binPath)
	if len(recs) != 3 {
		t.Errorf("want 3 records at cap, got %d", len(recs))
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 cap ScanError, got %d: %+v", len(errs), errs)
	}
}
