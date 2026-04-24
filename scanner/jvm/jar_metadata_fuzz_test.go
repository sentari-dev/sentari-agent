package jvm

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"
)

// FuzzParsePomProperties throws arbitrary bytes at the pom.properties
// parser.  The contract the fuzzer enforces: parser never panics and
// never hangs, regardless of input.  If it breaks these, we have a
// DoS primitive against the scanner via any planted pom.properties.
func FuzzParsePomProperties(f *testing.F) {
	f.Add([]byte("groupId=a\nartifactId=b\nversion=1\n"))
	f.Add([]byte("#comment only\n"))
	f.Add([]byte(""))
	f.Add([]byte("garbage=with=multiple=equals\n"))
	f.Add(bytes.Repeat([]byte("x"), maxPomPropertiesBytes+100))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parsePomProperties(data)
	})
}

// FuzzParseManifest does the same for MANIFEST.MF.  Continuation-line
// handling + mixed line endings are the two most error-prone parts of
// the parser; the fuzzer is there to find the case the author didn't
// consider.
func FuzzParseManifest(f *testing.F) {
	f.Add([]byte("Manifest-Version: 1.0\r\nBundle-SymbolicName: a\r\n"))
	f.Add([]byte("Manifest-Version: 1.0\nHeader: val\n continued\n"))
	f.Add([]byte(""))
	f.Add([]byte(":just a colon\r\n"))
	// Continuation line at the very start (before any header) — defensive.
	f.Add([]byte(" leading-continuation\r\n"))
	f.Add(bytes.Repeat([]byte("x: y\r\n"), 1000))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseManifest(data)
	})
}

// FuzzExtractFromJar ships an archive-level fuzzer: given bytes of a
// purported zip, write them to a temp file and run extractFromJar on
// the path.  The fuzzer exercises every entry-enumeration + reader
// path with adversarial inputs, which is harder to reach from the
// per-parser fuzzers above.
func FuzzExtractFromJar(f *testing.F) {
	// Seed with a minimal well-formed JAR.  We fail the fuzz setup
	// hard on any error — a silent nil pointer from the zip writer
	// defeats the point of fuzzing by crashing before the fuzzer
	// starts.
	var seed bytes.Buffer
	zw := zip.NewWriter(&seed)
	w, err := zw.Create("META-INF/maven/o/a/pom.properties")
	if err != nil {
		f.Fatalf("fuzz seed: create pom.properties entry: %v", err)
	}
	if _, err := w.Write([]byte("groupId=o\nartifactId=a\nversion=1\n")); err != nil {
		f.Fatalf("fuzz seed: write pom.properties entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		f.Fatalf("fuzz seed: finalise zip: %v", err)
	}
	f.Add(seed.Bytes())

	// Seed with non-zip garbage — the parser must produce a ScanError,
	// not panic.
	f.Add([]byte("not a zip at all"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp, err := os.CreateTemp(t.TempDir(), "fuzz-*.jar")
		if err != nil {
			t.Skip("cannot create temp file")
		}
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			t.Skip("cannot write temp file")
		}
		tmp.Close()
		// extractFromJar must return; it must not panic; it may return
		// a ScanError for unreadable input.  We don't assert on shape
		// — this fuzzer's job is purely crash-resistance.
		_, _ = extractFromJar(tmp.Name())
	})
}
