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
// per-parser fuzzers above.  Post-nested-traversal, this fuzzer also
// covers the recursion path — a mutated nested-jar member is a
// second-order attack surface.
func FuzzExtractFromJar(f *testing.F) {
	// Seed 1 — minimal well-formed JAR.
	var seed1 bytes.Buffer
	zw1 := zip.NewWriter(&seed1)
	w1, _ := zw1.Create("META-INF/maven/o/a/pom.properties")
	w1.Write([]byte("groupId=o\nartifactId=a\nversion=1\n"))
	zw1.Close()
	f.Add(seed1.Bytes())

	// Seed 2 — uber-jar with a valid nested JAR, so the fuzzer gets to
	// exercise the recursion path without having to re-discover the
	// ``entry ends in .jar → decompress → recurse`` chain from scratch.
	var inner bytes.Buffer
	izw := zip.NewWriter(&inner)
	iw, _ := izw.Create("META-INF/maven/n/inner/pom.properties")
	iw.Write([]byte("groupId=n\nartifactId=inner\nversion=2\n"))
	izw.Close()

	var seed2 bytes.Buffer
	zw2 := zip.NewWriter(&seed2)
	ow, _ := zw2.Create("META-INF/maven/o/outer/pom.properties")
	ow.Write([]byte("groupId=o\nartifactId=outer\nversion=1\n"))
	nw, _ := zw2.Create("BOOT-INF/lib/inner.jar")
	nw.Write(inner.Bytes())
	zw2.Close()
	f.Add(seed2.Bytes())

	// Seeds for obvious-garbage + empty inputs.
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
