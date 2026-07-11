package scanner

import (
	"path/filepath"
	"runtime"
	"testing"
)

// --- Finding portability-2: pyenv-win + PYENV_ROOT override ----------------

// containsRoot reports whether want is present in got.
func containsRoot(got []string, want string) bool {
	for _, g := range got {
		if g == want {
			return true
		}
	}
	return false
}

// pyenvVersionRootsFor must always keep the POSIX ~/.pyenv/versions entry and,
// on Windows, add the pyenv-win versions root (~/.pyenv/pyenv-win/versions).
// Because runtime.GOOS is a build constant, the goos-parameterised helper is
// exercised directly so the Windows branch is covered on any host.
func TestPyenvVersionRootsForGoos(t *testing.T) {
	const home = "/fake/home"

	posix := filepath.Join(home, ".pyenv", "versions")
	win := filepath.Join(home, ".pyenv", "pyenv-win", "versions")

	// POSIX host: POSIX path present, pyenv-win path absent.
	linux := pyenvVersionRootsFor(home, "linux")
	if !containsRoot(linux, posix) {
		t.Errorf("linux roots missing POSIX pyenv path %q: %v", posix, linux)
	}
	if containsRoot(linux, win) {
		t.Errorf("linux roots must NOT include pyenv-win path %q: %v", win, linux)
	}

	// Windows host: both the POSIX path and the pyenv-win path present.
	windows := pyenvVersionRootsFor(home, "windows")
	if !containsRoot(windows, posix) {
		t.Errorf("windows roots missing POSIX pyenv path %q: %v", posix, windows)
	}
	if !containsRoot(windows, win) {
		t.Errorf("windows roots missing pyenv-win path %q: %v", win, windows)
	}
}

// A PYENV_ROOT (POSIX) or PYENV (pyenv-win) override must be honoured on all
// platforms by appending <root>/versions, while keeping the default POSIX
// entry.  Duplicates (override == default) are collapsed.
func TestPyenvVersionRootsForHonoursEnvOverride(t *testing.T) {
	const home = "/fake/home"
	posix := filepath.Join(home, ".pyenv", "versions")

	t.Run("PYENV_ROOT", func(t *testing.T) {
		t.Setenv("PYENV", "")
		t.Setenv("PYENV_ROOT", "/custom/pyenv")
		roots := pyenvVersionRootsFor(home, runtime.GOOS)
		if !containsRoot(roots, filepath.Join("/custom/pyenv", "versions")) {
			t.Errorf("PYENV_ROOT override not honoured: %v", roots)
		}
		if !containsRoot(roots, posix) {
			t.Errorf("default POSIX pyenv path dropped after override: %v", roots)
		}
	})

	t.Run("PYENV_win_var", func(t *testing.T) {
		t.Setenv("PYENV_ROOT", "")
		t.Setenv("PYENV", `C:\pyenv-win`)
		roots := pyenvVersionRootsFor(home, "windows")
		if !containsRoot(roots, filepath.Join(`C:\pyenv-win`, "versions")) {
			t.Errorf("PYENV override not honoured: %v", roots)
		}
	})

	t.Run("override_equal_default_deduped", func(t *testing.T) {
		t.Setenv("PYENV", "")
		t.Setenv("PYENV_ROOT", filepath.Join(home, ".pyenv"))
		roots := pyenvVersionRootsFor(home, "linux")
		n := 0
		for _, r := range roots {
			if r == posix {
				n++
			}
		}
		if n != 1 {
			t.Errorf("POSIX pyenv path appears %d times, want 1 (dedup): %v", n, roots)
		}
	})
}

// --- Finding portability-1: virtualenvwrapper WORKON_HOME + Windows default -

// virtualenvwrapperRootFor must honour a WORKON_HOME override on every platform
// and otherwise fall back to the per-platform default: ~/.virtualenvs on POSIX
// and %USERPROFILE%\Envs (home/Envs) on Windows.  runtime.GOOS is a build
// constant, so the goos/env-parameterised core is exercised directly.
func TestVirtualenvwrapperRootFor(t *testing.T) {
	const home = "/fake/home"

	t.Run("workon_home_override_posix", func(t *testing.T) {
		got := virtualenvwrapperRootFor(home, "linux", "/custom/envs")
		if got != "/custom/envs" {
			t.Errorf("WORKON_HOME override not honoured (posix): got %q want %q", got, "/custom/envs")
		}
	})

	t.Run("workon_home_override_windows", func(t *testing.T) {
		const wh = `D:\venvs`
		got := virtualenvwrapperRootFor(home, "windows", wh)
		if got != wh {
			t.Errorf("WORKON_HOME override not honoured (windows): got %q want %q", got, wh)
		}
	})

	t.Run("default_posix", func(t *testing.T) {
		want := filepath.Join(home, ".virtualenvs")
		got := virtualenvwrapperRootFor(home, "linux", "")
		if got != want {
			t.Errorf("posix default: got %q want %q", got, want)
		}
	})

	t.Run("default_windows", func(t *testing.T) {
		want := filepath.Join(home, "Envs")
		got := virtualenvwrapperRootFor(home, "windows", "")
		if got != want {
			t.Errorf("windows default (virtualenvwrapper-win): got %q want %q", got, want)
		}
	})

	t.Run("blank_workon_home_falls_back", func(t *testing.T) {
		want := filepath.Join(home, ".virtualenvs")
		got := virtualenvwrapperRootFor(home, "darwin", "   ")
		if got != want {
			t.Errorf("whitespace WORKON_HOME should fall back to default: got %q want %q", got, want)
		}
	})
}

// TestVirtualenvwrapperRootHonoursEnv exercises the exported wrapper end-to-end
// through the process environment (env-injected) on the current host.
func TestVirtualenvwrapperRootHonoursEnv(t *testing.T) {
	const home = "/fake/home"

	t.Setenv("WORKON_HOME", "/env/injected/envs")
	if got := virtualenvwrapperRoot(home); got != "/env/injected/envs" {
		t.Errorf("virtualenvwrapperRoot did not honour WORKON_HOME env: got %q", got)
	}

	t.Setenv("WORKON_HOME", "")
	// With WORKON_HOME cleared the per-GOOS default applies.
	want := filepath.Join(home, ".virtualenvs")
	if runtime.GOOS == "windows" {
		want = filepath.Join(home, "Envs")
	}
	if got := virtualenvwrapperRoot(home); got != want {
		t.Errorf("virtualenvwrapperRoot default: got %q want %q", got, want)
	}
}
