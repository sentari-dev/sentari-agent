package runtimeversions

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	must(t, os.WriteFile(path, []byte(contents), 0o644))
}

func TestDetectNginxFromConfDir_pkgVersion(t *testing.T) {
	dir := t.TempDir()
	// nginx source-style layout: sbin/nginx + conf/nginx.conf
	must(t, os.MkdirAll(filepath.Join(dir, "sbin"), 0o755))
	must(t, os.MkdirAll(filepath.Join(dir, "conf"), 0o755))
	writeFile(t, filepath.Join(dir, "sbin", "nginx"), "\x7fELF...nginx/1.25.3...")
	writeFile(t, filepath.Join(dir, "conf", "nginx.conf"), "worker_processes auto;")

	got := DetectAllWebServers(context.Background(), []string{filepath.Dir(dir)},
		func(name string) string { return "" }) // no pkg -> byte-scan fallback

	if len(got) != 1 || got[0].Name != "nginx" {
		t.Fatalf("expected nginx, got %+v", got)
	}
	if got[0].Version != "1.25.3" {
		t.Fatalf("version from binary scan = %q want 1.25.3", got[0].Version)
	}
}

func TestDetectApacheFromPkg(t *testing.T) {
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "conf"), 0o755))
	writeFile(t, filepath.Join(dir, "conf", "httpd.conf"), "ServerRoot /etc/httpd")
	writeFile(t, filepath.Join(dir, "httpd"), "binary")

	got := DetectAllWebServers(context.Background(), []string{filepath.Dir(dir)},
		func(name string) string {
			if name == "httpd" || name == "apache2" {
				return "2.4.58"
			}
			return ""
		})
	if len(got) != 1 || got[0].Name != "apache-httpd" || got[0].Version != "2.4.58" {
		t.Fatalf("expected apache-httpd 2.4.58, got %+v", got)
	}
}

func TestDetectNginxFlatEtcLayout(t *testing.T) {
	root := t.TempDir()
	// Debian/Ubuntu and RHEL nginx package layout: flat /etc/nginx/nginx.conf,
	// no conf/ subdirectory and no sbin/nginx alongside the config.
	must(t, os.MkdirAll(filepath.Join(root, "nginx"), 0o755))
	writeFile(t, filepath.Join(root, "nginx", "nginx.conf"), "worker_processes auto;")

	got := DetectAllWebServers(context.Background(), []string{root},
		func(name string) string {
			if name == "nginx" {
				return "1.24.0"
			}
			return ""
		})
	if len(got) != 1 || got[0].Name != "nginx" || got[0].Version != "1.24.0" {
		t.Fatalf("expected nginx 1.24.0, got %+v", got)
	}
}

func TestDetectApache2FlatDebianLayout(t *testing.T) {
	root := t.TempDir()
	// Debian/Ubuntu apache2 package layout: flat /etc/apache2/apache2.conf,
	// no conf/ subdirectory.
	must(t, os.MkdirAll(filepath.Join(root, "apache2"), 0o755))
	writeFile(t, filepath.Join(root, "apache2", "apache2.conf"), "ServerRoot /etc/apache2")

	got := DetectAllWebServers(context.Background(), []string{root},
		func(name string) string {
			if name == "apache2" {
				return "2.4.58"
			}
			return ""
		})
	if len(got) != 1 || got[0].Name != "apache-httpd" || got[0].Version != "2.4.58" {
		t.Fatalf("expected apache-httpd 2.4.58, got %+v", got)
	}
}
