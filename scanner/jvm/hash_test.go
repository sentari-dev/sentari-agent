package jvm

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func writeJar(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestExtractFromJar_SingleCoordinateHashed proves a plain library jar (one
// coordinate) carries the file's SHA-256 (SBOM-completeness v2 §4.5).
func TestExtractFromJar_SingleCoordinateHashed(t *testing.T) {
	dir := t.TempDir()
	jarPath := filepath.Join(dir, "lib.jar")
	writeJar(t, jarPath, map[string]string{
		"META-INF/maven/o/a/pom.properties": "groupId=o\nartifactId=a\nversion=1\n",
	})
	raw, err := os.ReadFile(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])

	records, errs := extractFromJar(jarPath)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	if len(records) != 1 {
		t.Fatalf("expected exactly one coordinate; got %d: %+v", len(records), records)
	}
	if records[0].Sha256 != want {
		t.Errorf("sha256 = %q, want %q", records[0].Sha256, want)
	}
}

// TestExtractFromJar_UberJarNotHashed proves an uber/nested jar (multiple
// coordinates) carries NO artifact hash on any record — the outer file's hash
// is not the hash of each embedded library.
func TestExtractFromJar_UberJarNotHashed(t *testing.T) {
	dir := t.TempDir()

	var inner bytes.Buffer
	izw := zip.NewWriter(&inner)
	iw, _ := izw.Create("META-INF/maven/n/inner/pom.properties")
	_, _ = iw.Write([]byte("groupId=n\nartifactId=inner\nversion=2\n"))
	_ = izw.Close()

	jarPath := filepath.Join(dir, "uber.jar")
	writeJar(t, jarPath, map[string]string{
		"META-INF/maven/o/outer/pom.properties": "groupId=o\nartifactId=outer\nversion=1\n",
		"BOOT-INF/lib/inner.jar":                inner.String(),
	})

	records, _ := extractFromJar(jarPath)
	if len(records) < 2 {
		t.Fatalf("expected multiple coordinates from an uber jar; got %+v", records)
	}
	for _, r := range records {
		if r.Sha256 != "" {
			t.Errorf("uber-jar record %q must carry no hash; got %q", r.Name, r.Sha256)
		}
	}
}
