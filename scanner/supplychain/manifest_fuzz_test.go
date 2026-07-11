package supplychain

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Fuzz targets for the supply-chain manifest parsers.
//
// Both entrypoints read attacker-influenceable files off the local
// filesystem — a package.json inside a scanned node_modules, a .nuspec
// inside a scanned NuGet cache — so any panic or hang is a fleet-wide DoS on
// the scan cycle, and any signal fabricated from unparsable bytes corrupts
// the supply-chain report. Each target asserts two things on every input:
//
//   - the parser never panics (the fuzz harness catches panics as failures);
//   - every emitted signal carries a non-empty PackageName and the expected
//     ecosystem tag — the parsers must refuse to emit a coordinate-less
//     signal from garbage bytes.
//
// The bytes are written to a real package dir so the whole walk + safeio +
// Unmarshal path is exercised, not just the decoder in isolation.
//
// Run in CI: go test -run=^$ -fuzz=FuzzDetectNpmManifest   -fuzztime=15s ./scanner/supplychain/
//            go test -run=^$ -fuzz=FuzzDetectNuspecManifest -fuzztime=15s ./scanner/supplychain/
//
// To wire the mutation pass into .github/workflows/fuzz.yml (out of this
// change's file set), add these matrix rows:
//   - { target: FuzzDetectNpmManifest,   pkg: ./scanner/supplychain/ }
//   - { target: FuzzDetectNuspecManifest, pkg: ./scanner/supplychain/ }

func assertSignalsWellFormed(t *testing.T, signals []sigProjection, wantEco, label string) {
	t.Helper()
	for _, s := range signals {
		if s.name == "" {
			t.Errorf("%s: emitted a coordinate-less signal (empty PackageName): %+v", label, s)
		}
		if s.eco != wantEco {
			t.Errorf("%s: signal has ecosystem %q, want %q: %+v", label, s.eco, wantEco, s)
		}
	}
}

// sigProjection is a tiny projection used only to keep the fuzz assertion
// independent of the full SupplyChainSignal shape.
type sigProjection struct {
	name string
	eco  string
}

// FuzzDetectNpmManifest drives the JSON package.json parse inside
// DetectInNodeModules with arbitrary bytes. Malformed, truncated,
// wrong-typed, BOM-prefixed, and deeply-nested inputs must all terminate
// without panicking, and no signal may be fabricated from unparsable bytes.
func FuzzDetectNpmManifest(f *testing.F) {
	f.Add(`{"name":"foo","version":"1.0.0","scripts":{"postinstall":"node b.js"}}`)
	f.Add(`{"name":"foo","version":"1.0.0"}`)
	f.Add("\xef\xbb\xbf{\"name\":\"bommy\",\"scripts\":{\"install\":\"x\"}}") // UTF-8 BOM
	f.Add(`{"name":123,"scripts":"notamap"}`)
	f.Add(`{"name":`)
	f.Add(`}}}garbage@@@`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, raw string) {
		root := t.TempDir()
		pkgDir := filepath.Join(root, "pkg")
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Skip(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(raw), 0o600); err != nil {
			t.Skip(err)
		}
		signals, err := DetectInNodeModules(context.Background(), root)
		if err != nil {
			return
		}
		proj := make([]sigProjection, 0, len(signals))
		for _, s := range signals {
			proj = append(proj, sigProjection{name: s.PackageName, eco: s.Ecosystem})
		}
		assertSignalsWellFormed(t, proj, "npm", "fuzz-npm-manifest")
	})
}

// FuzzDetectNuspecManifest drives the XML .nuspec parse inside
// DetectInNuGetCache with arbitrary bytes. Malformed, truncated, wrong-shaped,
// and entity-laden XML must all terminate without panicking, and no signal
// may be fabricated from unparsable bytes.
func FuzzDetectNuspecManifest(f *testing.F) {
	f.Add(`<package><metadata><id>Foo</id><version>1.0.0</version></metadata></package>`)
	f.Add(`<package><metadata><id></id></metadata></package>`)
	f.Add(`<package><metadata><id>Foo`)
	f.Add(`not xml <<< >>>`)
	f.Add(`<other><metadata><id>Foo</id></metadata></other>`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, raw string) {
		root := t.TempDir()
		verDir := filepath.Join(root, "pkg", "1.0.0")
		if err := os.MkdirAll(verDir, 0o755); err != nil {
			t.Skip(err)
		}
		if err := os.WriteFile(filepath.Join(verDir, "Pkg.nuspec"), []byte(raw), 0o600); err != nil {
			t.Skip(err)
		}
		signals, err := DetectInNuGetCache(context.Background(), root)
		if err != nil {
			return
		}
		proj := make([]sigProjection, 0, len(signals))
		for _, s := range signals {
			proj = append(proj, sigProjection{name: s.PackageName, eco: s.Ecosystem})
		}
		assertSignalsWellFormed(t, proj, "nuget", "fuzz-nuspec-manifest")
	})
}
