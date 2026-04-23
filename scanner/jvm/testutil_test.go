package jvm

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// buildJAR is the fixture helper for every jar_metadata test.  Rather
// than check in binary .jar fixtures for each case (which ages badly
// and is opaque to reviewers), we describe each fixture declaratively
// and build it in memory here.  ``entries`` maps archive path to
// bytes; the function writes the archive to a temp file and returns
// the path for the test to pass to extractFromJar().
//
// Every call uses t.TempDir() so the OS cleans up when the test
// exits; no teardown boilerplate in the caller.
func buildJAR(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("buildJAR: create %q: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("buildJAR: write %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("buildJAR: close zip: %v", err)
	}
	path := filepath.Join(t.TempDir(), "fixture.jar")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("buildJAR: write file: %v", err)
	}
	return path
}
