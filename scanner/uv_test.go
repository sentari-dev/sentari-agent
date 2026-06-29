package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writePyvenvCfg(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "pyvenv.cfg")
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatalf("write pyvenv.cfg: %v", err)
	}
	return cfg
}

func TestIsUvVenv(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "uv-managed venv",
			body: "home = /usr/bin\nimplementation = CPython\nuv = 0.4.18\nversion_info = 3.12.4\n",
			want: true,
		},
		{
			name: "uv key no spaces",
			body: "home = /usr/bin\nuv=0.5.0\n",
			want: true,
		},
		{
			name: "plain cpython venv",
			body: "home = /usr/bin\nimplementation = CPython\nversion_info = 3.11.0\ninclude-system-site-packages = false\n",
			want: false,
		},
		{
			name: "no uv key but uv substring elsewhere",
			body: "home = /opt/uv-cache/python\nversion = 3.12.0\n",
			want: false,
		},
		{
			name: "empty file",
			body: "",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writePyvenvCfg(t, tc.body)
			if got := isUvVenv(cfg); got != tc.want {
				t.Errorf("isUvVenv(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestIsUvVenvMissingFile(t *testing.T) {
	if isUvVenv(filepath.Join(t.TempDir(), "does-not-exist", "pyvenv.cfg")) {
		t.Error("isUvVenv should be false when pyvenv.cfg is absent")
	}
}
