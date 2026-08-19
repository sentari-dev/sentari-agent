package gobinaries

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func moduleNames(recs []recordish) map[string]string {
	m := map[string]string{}
	for _, r := range recs {
		m[r.name] = r.version
	}
	return m
}

func TestProbeBinary_RealGoBinary(t *testing.T) {
	bin := hostFixtureBinary(t)
	recs, errs := probeBinary(bin)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	names := moduleNames(toRecordish(recs))
	if v, ok := names[fixtureMainModule]; !ok {
		t.Errorf("main module %q missing; got %v", fixtureMainModule, names)
	} else if v != fixtureModuleVersion {
		t.Errorf("main version = %q, want %q", v, fixtureModuleVersion)
	}
	// The local directory replace resolves to path "./fakedep"; per the
	// replace rule we emit the replacement path verbatim.
	if _, ok := names[fixtureReplacePath]; !ok {
		t.Errorf("replaced dep %q missing; got %v", fixtureReplacePath, names)
	}
	if _, ok := names["stdlib"]; !ok {
		t.Errorf("stdlib toolchain record missing; got %v", names)
	}
	// Every record must point install_path at the probed binary.
	for _, r := range toRecordish(recs) {
		if r.installPath != bin {
			t.Errorf("record %q install_path = %q, want %q", r.name, r.installPath, bin)
		}
	}
}

func TestProbeBinary_CrossFormatELF_PE_MachO(t *testing.T) {
	want := map[string]bool{fixtureMainModule: true, fixtureReplacePath: true, "stdlib": true}
	for _, goos := range []string{"linux", "windows", "darwin"} {
		bin := buildFixtureBinary(t, goos)
		recs, errs := probeBinary(bin)
		if len(errs) != 0 {
			t.Fatalf("[%s] unexpected errors: %+v", goos, errs)
		}
		names := moduleNames(toRecordish(recs))
		for w := range want {
			if _, ok := names[w]; !ok {
				t.Errorf("[%s] module %q missing; got %v", goos, w, names)
			}
		}
	}
}

func TestProbeBinary_NonGoBinarySkippedSilently(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fakeelf")
	// Valid ELF magic, garbage body — not a Go executable.
	body := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 512)...)
	if err := os.WriteFile(p, body, 0o755); err != nil {
		t.Fatal(err)
	}
	recs, errs := probeBinary(p)
	if len(recs) != 0 || len(errs) != 0 {
		t.Errorf("non-Go binary must be skipped silently; got %d recs, %d errs", len(recs), len(errs))
	}
}

func TestProbeBinary_ScriptSkippedByMagicSniff(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	recs, errs := probeBinary(p)
	if len(recs) != 0 || len(errs) != 0 {
		t.Errorf("script must be skipped before any parse; got %d recs, %d errs", len(recs), len(errs))
	}
}

func TestProbeBinary_SymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	bin := hostFixtureBinary(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	recs, errs := probeBinary(link)
	if len(recs) != 0 {
		t.Errorf("symlink must yield no records; got %d", len(recs))
	}
	if len(errs) != 0 {
		t.Errorf("symlink is skipped, not diagnosed; got errs %+v", errs)
	}
}

func TestProbeBinary_OversizeSkippedWithScanError(t *testing.T) {
	orig := maxGoBinaryBytes
	maxGoBinaryBytes = 1024
	defer func() { maxGoBinaryBytes = orig }()

	bin := hostFixtureBinary(t)
	recs, errs := probeBinary(bin)
	if len(recs) != 0 {
		t.Errorf("oversize binary must yield no records; got %d", len(recs))
	}
	if len(errs) != 1 {
		t.Fatalf("oversize binary must emit exactly one ScanError; got %d: %+v", len(errs), errs)
	}
}
