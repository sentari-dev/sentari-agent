package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Scanner discovers Python environments and extracts package metadata.
type Scanner struct {
	cfg Config
}

// NewScanner creates a scanner with the given configuration.
// Zero values for MaxDepth default to 12, and MaxWorkers default to 8.
func NewScanner(cfg Config) *Scanner {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 12
	}
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = 8
	}
	if cfg.ScanRoot == "" {
		cfg.ScanRoot = "/"
		if runtime.GOOS == "windows" {
			cfg.ScanRoot = "C:\\"
		}
	}
	return &Scanner{cfg: cfg}
}

// scanJobResult collects packages and errors from a single environment scan.
type scanJobResult struct {
	packages []PackageRecord
	errors   []ScanError
}

// Run performs a full scan of the device. It walks the filesystem from
// ScanRoot up to MaxDepth, discovers Python environments, and dispatches
// environment-specific parsers via a bounded worker pool.
func (s *Scanner) Run(ctx context.Context) (*ScanResult, error) {
	result := &ScanResult{
		DeviceID:     GetDeviceID(),
		Hostname:     getHostname(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		ScannedAt:    time.Now().UTC(),
		Packages:     make([]PackageRecord, 0, 256),
		Errors:       make([]ScanError, 0),
		AgentVersion: Version,
	}

	// Phase 1: discover all Python environments on the filesystem.
	envs, discoveryErrors := s.discoverEnvironments(ctx)
	result.Errors = append(result.Errors, discoveryErrors...)

	if len(envs) == 0 {
		return result, nil
	}

	// Phase 2: scan each environment in parallel using a bounded worker pool.
	jobs := make(chan discoveredEnv, len(envs))
	results := make(chan scanJobResult, len(envs))

	var wg sync.WaitGroup
	for i := 0; i < s.cfg.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for env := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					res := s.scanEnvironment(env)
					results <- res
				}
			}
		}()
	}

	// Enqueue all discovered environments.
	for _, env := range envs {
		jobs <- env
	}
	close(jobs)

	// Wait for all workers, then close results.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results.
	for res := range results {
		result.Packages = append(result.Packages, res.packages...)
		result.Errors = append(result.Errors, res.errors...)
	}

	return result, nil
}

// scanEnvironment dispatches to the correct environment-specific parser.
func (s *Scanner) scanEnvironment(env discoveredEnv) scanJobResult {
	var pkgs []PackageRecord
	var errs []ScanError

	switch env.envType {
	case EnvPip, EnvVenv:
		pkgs, errs = scanPipEnvironment(env.path)
		// scanPipEnvironment always tags packages as EnvPip.
		// Override with the actual discovered env type so that venvs
		// are correctly reported as "venv" to the server.
		if env.envType == EnvVenv {
			for i := range pkgs {
				pkgs[i].EnvType = EnvVenv
			}
		}
	case EnvConda:
		pkgs, errs = scanCondaEnvironment(env.path)
	case EnvPoetry:
		pkgs, errs = scanPoetryEnvironment(env.path)
	case EnvPipenv:
		pkgs, errs = scanPipenvEnvironment(env.path)
	case EnvSystemDeb:
		pkgs, errs = scanDebianPackages()
	case EnvSystemRpm:
		pkgs, errs = scanRpmPackages()
	default:
		errs = append(errs, ScanError{
			Path:      env.path,
			EnvType:   env.envType,
			Error:     fmt.Sprintf("unknown environment type: %s", env.envType),
			Timestamp: time.Now().UTC(),
		})
	}

	return scanJobResult{packages: pkgs, errors: errs}
}

// resolveKey returns a canonical path for deduplication.  It resolves
// symlinks so that, for example, /opt/homebrew/… and
// /System/Volumes/Data/opt/homebrew/… (macOS firmlinks) map to the same
// key.  On failure it falls back to filepath.Clean.
func resolveKey(p string) string {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return resolved
}

// extraScanRoots returns additional filesystem roots that should be scanned
// for Python environments. These cover well-known version managers (pyenv, asdf)
// that install Python in deep directory trees which the main walk might miss
// depending on MaxDepth and scan root configuration.
//
// homeDir is the user's home directory (or any directory to check under).
// Only paths that actually exist on disk are returned.
func extraScanRoots(homeDir string) []string {
	candidates := []string{
		filepath.Join(homeDir, ".pyenv", "versions"),
		filepath.Join(homeDir, ".asdf", "installs", "python"),
	}

	var roots []string
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			roots = append(roots, c)
		}
	}
	return roots
}

// userHomeDirs returns home directories to check for version manager
// installations. On most systems this is just the current user's home.
// We also scan /home/* on Linux to cover multi-user servers where the
// agent runs as root.
func userHomeDirs() []string {
	var dirs []string

	// Current user's home directory.
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, home)
	}

	// On Linux, scan all home directories if running as a privileged user.
	// The agent commonly runs as root via systemd on managed fleets.
	if runtime.GOOS == "linux" {
		if entries, err := os.ReadDir("/home"); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					candidate := filepath.Join("/home", entry.Name())
					dirs = append(dirs, candidate)
				}
			}
		}
	}

	// Deduplicate (current user's home may be /home/<user>).
	seen := make(map[string]bool, len(dirs))
	unique := dirs[:0]
	for _, d := range dirs {
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}
	return unique
}

// discoverEnvironments walks the filesystem from ScanRoot and identifies
// Python environment locations by looking for marker files and directories.
// Discovery is single-threaded because directory traversal is I/O-bound on
// a single disk; parallelism is used in the scanning phase instead.
func (s *Scanner) discoverEnvironments(ctx context.Context) ([]discoveredEnv, []ScanError) {
	var envs []discoveredEnv
	var errs []ScanError
	seen := make(map[string]bool)

	// rootDepth is used by the walk closure to calculate depth relative to the
	// current walk root. It is updated before each extra-root walk so that
	// version-manager directories get a full MaxDepth budget of their own.
	rootDepth := strings.Count(filepath.Clean(s.cfg.ScanRoot), string(os.PathSeparator))

	// Directories that are never useful and slow down scanning.
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "__pycache__": true,
		".cache": true, "proc": true, "sys": true, "dev": true,
		"run": true, "tmp": true, ".hg": true, ".svn": true,
		".pytest_cache": true, ".tox": true, ".mypy_cache": true,
		".ruff_cache": true,
	}
	// NOTE: .venv is NOT skipped — it's a valid Python virtualenv.

	// Absolute paths to skip — prevents duplicate discovery on macOS
	// where /System/Volumes/Data is a firmlink mirror of /.
	skipAbsPaths := map[string]bool{
		"/System/Volumes/Data": true,
	}

	var walk func(path string) error
	walk = func(path string) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Enforce max depth.
		currentDepth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - rootDepth
		if currentDepth > s.cfg.MaxDepth {
			return nil
		}

		base := filepath.Base(path)
		if skipDirs[base] {
			return nil
		}
		if skipAbsPaths[path] {
			return nil
		}

		// Check for pyvenv.cfg → venv / virtualenv.
		pyvenvCfg := filepath.Join(path, "pyvenv.cfg")
		if _, err := os.Stat(pyvenvCfg); err == nil {
			// Verify the venv isn't broken (dangling symlink to an
			// uninstalled interpreter).  A venv whose base Python has
			// been removed is useless — skip it and record a warning.
			if reason := isVenvDangling(path, pyvenvCfg); reason != "" {
				errs = append(errs, ScanError{
					Path:      path,
					EnvType:   EnvVenv,
					Error:     reason,
					Timestamp: time.Now().UTC(),
				})
				return nil // Skip this venv entirely.
			}

			key := resolveKey(path)
			if !seen[key] {
				seen[key] = true
				envs = append(envs, discoveredEnv{
					path:    path,
					envType: EnvVenv,
					name:    base,
				})
			}
			return nil // Don't recurse into venvs.
		}

		// Check for conda-meta directory.
		condaMeta := filepath.Join(path, "conda-meta")
		if info, err := os.Stat(condaMeta); err == nil && info.IsDir() {
			key := resolveKey(condaMeta)
			if !seen[key] {
				seen[key] = true
				envs = append(envs, discoveredEnv{
					path:    path,
					envType: EnvConda,
					name:    base,
				})
			}
			return nil // Don't recurse into conda envs.
		}

		// Check for poetry.lock.
		poetryLock := filepath.Join(path, "poetry.lock")
		if _, err := os.Stat(poetryLock); err == nil {
			key := resolveKey(poetryLock)
			if !seen[key] {
				seen[key] = true
				envs = append(envs, discoveredEnv{
					path:    path,
					envType: EnvPoetry,
					name:    base,
				})
			}
			// Don't return — a project can have poetry.lock AND subdirs to scan.
		}

		// Check for Pipfile.lock.
		pipfileLock := filepath.Join(path, "Pipfile.lock")
		if _, err := os.Stat(pipfileLock); err == nil {
			key := resolveKey(pipfileLock)
			if !seen[key] {
				seen[key] = true
				envs = append(envs, discoveredEnv{
					path:    path,
					envType: EnvPipenv,
					name:    base,
				})
			}
		}

		// Check for site-packages (global pip).
		if base == "site-packages" {
			key := resolveKey(path)
			if !seen[key] {
				seen[key] = true
				envs = append(envs, discoveredEnv{
					path:    path,
					envType: EnvPip,
					name:    "global",
				})
			}
			return nil // Don't recurse into site-packages.
		}

		// Recurse into subdirectories.
		entries, err := os.ReadDir(path)
		if err != nil {
			// Permission denied is expected when scanning as a non-root user
			// (e.g. /root, /etc/ssl/private). Skip silently — not actionable.
			if !os.IsPermission(err) {
				errs = append(errs, ScanError{
					Path:      path,
					Error:     fmt.Sprintf("readdir: %v", err),
					Timestamp: time.Now().UTC(),
				})
			}
			return nil // Continue regardless.
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			// Skip symlinked directories to prevent traversal escape (a symlink
			// to / or to a parent directory could cause infinite loops) and to
			// avoid scanning outside the intended scan root.
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			if err := walk(filepath.Join(path, entry.Name())); err != nil {
				return err // Propagate context cancellation.
			}
		}

		return nil
	}

	_ = walk(s.cfg.ScanRoot)

	// Scan well-known version manager directories (pyenv, asdf) that may be
	// too deep for the main walk to reach.
	//
	// When the scan root is "/" (full system scan), also check the real user
	// home directories via userHomeDirs(). When the scan root is a specific
	// directory (e.g., /opt/app or a test temp dir), only check directories
	// under the scan root — never escape to unrelated system paths.
	var extraHomes []string
	cleanRoot := filepath.Clean(s.cfg.ScanRoot)
	if cleanRoot == "/" || (runtime.GOOS == "windows" && len(cleanRoot) <= 3) {
		extraHomes = userHomeDirs()
	}
	// Check directories directly under the scan root for version manager
	// patterns (handles cases where scan root is /home/user or similar).
	if topEntries, err := os.ReadDir(s.cfg.ScanRoot); err == nil {
		for _, e := range topEntries {
			if e.IsDir() {
				extraHomes = append(extraHomes, filepath.Join(s.cfg.ScanRoot, e.Name()))
			}
		}
	}
	// Also check the scan root itself.
	extraHomes = append(extraHomes, s.cfg.ScanRoot)
	// Walk each extra root with its own depth budget. We set rootDepth to the
	// depth of the extra root itself so that MaxDepth is measured from the
	// extra root, not from s.cfg.ScanRoot. Version manager directories like
	// .pyenv/versions/3.12.0/lib/python3.12/site-packages are 4+ levels deep,
	// so we use a minimum effective MaxDepth of 8 for extra roots regardless
	// of the configured MaxDepth — the caller's shallow MaxDepth is intended
	// to limit the main walk, not these explicit well-known paths.
	mainRootDepth := rootDepth
	savedMaxDepth := s.cfg.MaxDepth
	if s.cfg.MaxDepth < 8 {
		s.cfg.MaxDepth = 8
	}
	for _, home := range extraHomes {
		for _, extra := range extraScanRoots(home) {
			rootDepth = strings.Count(filepath.Clean(extra), string(os.PathSeparator))
			_ = walk(extra)
		}
	}
	rootDepth = mainRootDepth
	s.cfg.MaxDepth = savedMaxDepth

	// Add system package manager jobs (Linux only, full-system scan).
	// Only check when ScanRoot is / — otherwise the user is scanning a
	// specific directory and doesn't want system-wide dpkg/rpm results.
	if runtime.GOOS == "linux" && (cleanRoot == "/") {
		if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
			envs = append(envs, discoveredEnv{path: "/var/lib/dpkg", envType: EnvSystemDeb, name: "dpkg"})
		}
		if _, err := os.Stat("/var/lib/rpm"); err == nil {
			envs = append(envs, discoveredEnv{path: "/var/lib/rpm", envType: EnvSystemRpm, name: "rpm"})
		}
	}

	// Add Windows Registry-discovered Python installations.
	// Returns (nil, nil) on non-Windows — see system_others.go.
	regEnvs, regErrs := discoverWindowsRegistryEnvs()
	envs = append(envs, regEnvs...)
	errs = append(errs, regErrs...)

	return envs, errs
}

// isVenvDangling checks whether a virtualenv's Python interpreter is still
// reachable.  Returns a human-readable reason string if the venv is broken,
// or "" if it looks healthy.
//
// Strategy (fast, no subprocess):
//  1. Parse pyvenv.cfg for the "home" key — the directory that contains the
//     base Python interpreter.  If the directory no longer exists the venv is
//     dangling.
//  2. Check if <venv>/bin/python (Unix) or <venv>/Scripts/python.exe (Windows)
//     is a dangling symlink.  os.Lstat succeeds on a symlink even if the
//     target is gone, but os.Stat (which follows symlinks) will fail.
func isVenvDangling(venvPath, pyvenvCfgPath string) string {
	// Check 1: pyvenv.cfg "home" key.
	if f, err := os.Open(pyvenvCfgPath); err == nil {
		defer f.Close()
		scn := bufio.NewScanner(f)
		for scn.Scan() {
			line := strings.TrimSpace(scn.Text())
			if strings.HasPrefix(line, "home") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					homeDir := strings.TrimSpace(parts[1])
					if _, err := os.Stat(homeDir); os.IsNotExist(err) {
						return fmt.Sprintf("dangling venv: base Python directory %s no longer exists", homeDir)
					}
				}
				break
			}
		}
	}

	// Check 2: detect dangling symlink on the venv's own python binary.
	// If the binary doesn't exist at all (e.g. minimal/test venvs), that's
	// fine — we only flag it when a symlink is present but its target is gone.
	var pythonBin string
	if runtime.GOOS == "windows" {
		pythonBin = filepath.Join(venvPath, "Scripts", "python.exe")
	} else {
		pythonBin = filepath.Join(venvPath, "bin", "python")
	}

	// os.Lstat does NOT follow symlinks; if it succeeds the path entry exists.
	if linfo, lstatErr := os.Lstat(pythonBin); lstatErr == nil {
		// The entry exists. If it's a symlink, verify the target is reachable.
		if linfo.Mode()&os.ModeSymlink != 0 {
			if _, statErr := os.Stat(pythonBin); statErr != nil {
				// Symlink exists but target is gone → dangling.
				target, _ := os.Readlink(pythonBin)
				return fmt.Sprintf("dangling venv: python symlink %s → %s is broken", pythonBin, target)
			}
		}
		// Not a symlink (or symlink with valid target) → healthy.
	}
	// pythonBin not present at all → not dangling (just incomplete; pyvenv.cfg home was OK).

	return ""
}

// GetDeviceID returns a stable unique device identifier.
// Linux: reads /etc/machine-id.
// Windows: reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid via registry.
// Falls back to hostname on any other OS or error.
func GetDeviceID() string {
	switch runtime.GOOS {
	case "linux":
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	case "windows":
		// readWindowsMachineGUID is defined in system_windows.go /
		// system_others.go (returns "" on non-Windows).
		if id := readWindowsMachineGUID(); id != "" {
			return id
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

// getHostname returns the system hostname.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
