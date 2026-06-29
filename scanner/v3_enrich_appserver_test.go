package scanner

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrichWithV3_DetectsAppServer(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "apache-tomcat-10.1.18")
	if err := os.MkdirAll(filepath.Join(home, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Minimal catalina.jar with a manifest carrying the version.
	writeCatalinaJar(t, filepath.Join(home, "lib", "catalina.jar"), "10.1.18")

	t.Setenv("CATALINA_HOME", home)
	var res ScanResult
	enrichWithV3(&res, nil) // app-server detection reads CATALINA_HOME directly

	found := false
	for _, r := range res.InstalledRuntimes {
		if r.Name == "tomcat" && r.Version == "10.1.18" && r.Cycle == "10.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("tomcat 10.1.18 not in %+v", res.InstalledRuntimes)
	}
}

func writeCatalinaJar(t *testing.T, path, version string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("Manifest-Version: 1.0\nImplementation-Version: " + version + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}
