package deptree

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// parserUnderTest pairs a deptree parser with a sample valid body for
// the lockfile it consumes. Each parser MUST route its reads through
// safeio so that (a) a symlinked lockfile is refused and (b) an
// oversize lockfile is refused.  These two red-team assertions mirror
// scanner/safeio's own tests.
type parserUnderTest struct {
	name string
	body string
	// call invokes the parser against `path`; for parsers that take a
	// second path argument (yarn -> package.json, maven -> m2 dir) the
	// helper supplies a throwaway second arg.
	call func(path string) error
}

func deptreeParsers() []parserUnderTest {
	return []parserUnderTest{
		{
			name: "uv.lock",
			body: "[[package]]\nname = \"a\"\nversion = \"1.0\"\n",
			call: func(p string) error { _, err := ParseUvLock(p); return err },
		},
		{
			name: "poetry.lock",
			body: "[[package]]\nname = \"a\"\nversion = \"1.0\"\n",
			call: func(p string) error { _, err := ParsePoetryLock(p); return err },
		},
		{
			name: "Pipfile.lock",
			body: `{"default":{"a":{"version":"==1.0"}}}`,
			call: func(p string) error { _, err := ParsePipfileLock(p); return err },
		},
		{
			name: "requirements.txt",
			body: "a==1.0\n",
			call: func(p string) error { _, err := ParseRequirementsTxt(p); return err },
		},
		{
			name: "package-lock.json",
			body: `{"lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0"}}}`,
			call: func(p string) error { _, err := ParseNpmPackageLock(p); return err },
		},
		{
			name: "yarn.lock",
			body: "a@^1.0.0:\n  version \"1.0.0\"\n",
			call: func(p string) error {
				_, err := ParseYarnLock(p, filepath.Join(filepath.Dir(p), "package.json"))
				return err
			},
		},
		{
			name: "pnpm-lock.yaml",
			body: "lockfileVersion: '6.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1.0.0\n        version: 1.0.0\npackages:\n  /a@1.0.0:\n    resolution: {integrity: sha512-x}\n",
			call: func(p string) error { _, err := ParsePnpmLock(p); return err },
		},
		{
			name: "project.assets.json",
			body: `{"version":3,"targets":{},"project":{}}`,
			call: func(p string) error { _, err := ParseNuGetProjectAssets(p); return err },
		},
		{
			name: "packages.lock.json",
			body: `{"version":1,"dependencies":{}}`,
			call: func(p string) error { _, err := ParseNuGetPackagesLock(p); return err },
		},
		{
			name: "pom.xml",
			body: `<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>`,
			call: func(p string) error { _, err := ParseMavenPom(p, filepath.Join(filepath.Dir(p), ".m2")); return err },
		},
	}
}

func TestDeptreeParsers_RefuseSymlinkedLockfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation on Windows requires admin")
	}
	for _, p := range deptreeParsers() {
		t.Run(p.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target-"+p.name)
			if err := os.WriteFile(target, []byte(p.body), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, p.name)
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink creation not permitted: %v", err)
			}
			err := p.call(link)
			if err == nil {
				t.Fatalf("%s: expected read of symlinked lockfile to be refused, got nil", p.name)
			}
			if !errors.Is(err, safeio.ErrSymlink) {
				t.Fatalf("%s: expected ErrSymlink, got %v", p.name, err)
			}
		})
	}
}

func TestDeptreeParsers_RefuseOversizeLockfile(t *testing.T) {
	// Write the oversize file ONCE and reuse it across every parser:
	// safeio rejects on size before any byte reaches the parser, so the
	// file's basename/content is irrelevant.  Writing 50 MiB per subtest
	// would make this test take well over a minute.
	dir := t.TempDir()
	huge := strings.Repeat("a", (maxLockfileBytes)+1) // 50 MiB + 1 byte
	path := filepath.Join(dir, "oversize.lock")
	if err := os.WriteFile(path, []byte(huge), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range deptreeParsers() {
		t.Run(p.name, func(t *testing.T) {
			err := p.call(path)
			if err == nil {
				t.Fatalf("%s: expected oversize lockfile to be refused, got nil", p.name)
			}
			if !errors.Is(err, safeio.ErrTooLarge) {
				t.Fatalf("%s: expected ErrTooLarge, got %v", p.name, err)
			}
		})
	}
}
