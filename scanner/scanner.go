package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Runner discovers Python environments and extracts package metadata by
// driving the registered Scanner plugins (see registry.go).  It owns the
// filesystem walk, the bounded worker pool, and the ScanResult assembly.
type Runner struct {
	cfg Config
}

// NewRunner creates a scan runner with the given configuration.
// Zero values for MaxDepth default to 12, and MaxWorkers default to 8.
func NewRunner(cfg Config) *Runner {
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
	return &Runner{cfg: cfg}
}

// NewScanner is a deprecated alias for NewRunner kept for backwards-compat
// with pre-registry callers.  New code should call NewRunner.
//
// Deprecated: use NewRunner.
func NewScanner(cfg Config) *Runner { return NewRunner(cfg) }

// scanJobResult collects packages and errors from a single environment scan.
type scanJobResult struct {
	packages []PackageRecord
	errors   []ScanError
}


// Run performs a full scan of the device. It walks the filesystem from
// ScanRoot up to MaxDepth, discovers Python environments, and dispatches
// environment-specific parsers via a bounded worker pool.
func (r *Runner) Run(ctx context.Context) (*ScanResult, error) {
	// Plumb the configured scan root through to scanners that care about
	// scope (dpkg, rpm — see IsFullSystemScan).  Scanners that don't
	// ignore it.
	ctx = WithScanRoot(ctx, r.cfg.ScanRoot)

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
	envs, discoveryErrors := r.discoverEnvironments(ctx)
	result.Errors = append(result.Errors, discoveryErrors...)

	if len(envs) == 0 {
		return result, nil
	}

	// Phase 2: scan each environment in parallel using a bounded worker pool.
	jobs := make(chan Environment, len(envs))
	results := make(chan scanJobResult, len(envs))

	var wg sync.WaitGroup
	for i := 0; i < r.cfg.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for env := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					res := r.scanEnvironment(ctx, env)
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

	// Phase 3 (v3 payload): cross-ecosystem enrichment.
	//
	// Runs after the v2 worker pool finishes so the existing scan
	// surface (packages, errors) is unaffected by any v3 module
	// failure.  All four new fields default to nil/empty when the
	// modules find nothing relevant for this host.
	//
	// Root selection: when the operator runs a scoped scan (e.g.
	// ``--scan /opt/app``), we honour that scope.  When the scan
	// root is filesystem root (``/`` on POSIX, drive root on
	// Windows), we substitute user home directories — lockfile
	// discovery walking ``/`` would be prohibitively expensive
	// on production hosts and most lockfiles live under user
	// home + repo trees anyway.
	v3Roots := v3DiscoveryRoots(r.cfg.ScanRoot)
	enrichWithV3(result, v3Roots)

	// macOS TCC warning: when running as root (launchd daemon) with a full
	// system scan, TCC silently blocks access to ~/Documents, ~/Desktop,
	// and ~/Downloads unless the binary has Full Disk Access. The scanner
	// sees these directories as empty — no permission error, just missing
	// packages. Warn operators so they know to grant FDA.
	if runtime.GOOS == "darwin" && os.Getuid() == 0 && filepath.Clean(r.cfg.ScanRoot) == "/" {
		for _, home := range userHomeDirs() {
			docsDir := filepath.Join(home, "Documents")
			if info, err := os.Stat(docsDir); err == nil && info.IsDir() {
				entries, _ := os.ReadDir(docsDir)
				if len(entries) == 0 {
					// A user home with an empty Documents/ is almost certainly
					// TCC blocking access, not a genuinely empty directory.
					msg := fmt.Sprintf(
						"macOS TCC: %s appears empty (likely blocked by Transparency, Consent, and Control). "+
							"Grant Full Disk Access to /usr/local/bin/sentari-agent in "+
							"System Settings → Privacy & Security → Full Disk Access "+
							"to scan Python environments in user project folders.",
						docsDir,
					)
					fmt.Fprintln(os.Stderr, "WARNING: "+msg)
					result.Errors = append(result.Errors, ScanError{
						Path:      docsDir,
						EnvType:   "tcc",
						Error:     msg,
						Timestamp: time.Now().UTC(),
					})
				}
			}
		}
	}

	return result, nil
}

// scanEnvironment looks up the scanner that produced env and delegates to
// its Scan method.  This is the sole dispatch path after the Sprint 13
// plugin-registry refactor — there are no switch arms over EnvType.
//
// A panic inside a per-ecosystem parser (malformed package DB, parser
// bug on an unexpected fixture) is caught here and turned into a
// typed ScanError.  Without the recover, a single malformed .deb or
// a corrupt RPM header would abort the whole scan cycle and force
// the cached-scan drain path — the scan_errors surface is exactly
// where this belongs.
func (r *Runner) scanEnvironment(ctx context.Context, env Environment) (result scanJobResult) {
	s := scannerFor(env.EnvType)
	if s == nil {
		return scanJobResult{errors: []ScanError{{
			Path:      env.Path,
			EnvType:   env.EnvType,
			Error:     fmt.Sprintf("no scanner registered for env_type %q", env.EnvType),
			Timestamp: time.Now().UTC(),
		}}}
	}
	defer func() {
		if rec := recover(); rec != nil {
			result = scanJobResult{errors: []ScanError{{
				Path:      env.Path,
				EnvType:   env.EnvType,
				Error:     fmt.Sprintf("scanner panic: %v", rec),
				Timestamp: time.Now().UTC(),
			}}}
		}
	}()
	pkgs, errs := s.Scan(ctx, env)
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

	// On Linux/macOS, scan all home directories if running as a privileged
	// user. The agent commonly runs as root via systemd (Linux) or launchd
	// (macOS) on managed fleets. Without this, os.UserHomeDir() returns
	// /var/root on macOS and the scanner misses all user-local venvs.
	homeBases := []string{}
	switch runtime.GOOS {
	case "linux":
		homeBases = append(homeBases, "/home")
	case "darwin":
		homeBases = append(homeBases, "/Users")
	}
	for _, base := range homeBases {
		if entries, err := os.ReadDir(base); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					name := entry.Name()
					// Skip macOS system accounts and hidden directories.
					if name == "Shared" || name == "Guest" || strings.HasPrefix(name, ".") {
						continue
					}
					dirs = append(dirs, filepath.Join(base, name))
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
// Python environment locations by consulting the registered MarkerScanners.
// Each directory the walker visits is offered to every marker scanner in
// registration order; a scanner that matches contributes an Environment
// (and optionally a Warning) and may ask the walker not to descend.
//
// Discovery is single-threaded — directory traversal is I/O-bound on a
// single disk, and parallelism is used in the scanning phase instead.
// The RootScanners (dpkg, rpm, Windows registry) are invoked after the
// walk completes.
func (r *Runner) discoverEnvironments(ctx context.Context) ([]Environment, []ScanError) {
	var envs []Environment
	var errs []ScanError
	seen := make(map[string]bool)

	// Snapshot the marker scanners once — registration is init()-only
	// so the set can't change during a run, but a slice snapshot keeps
	// the hot path out of the registry RWMutex.
	markers := markerScanners()

	// rootDepth is used by the walk closure to calculate depth relative to the
	// current walk root. It is updated before each extra-root walk so that
	// version-manager directories get a full MaxDepth budget of their own.
	rootDepth := strings.Count(filepath.Clean(r.cfg.ScanRoot), string(os.PathSeparator))

	// Directories that are never useful and slow down scanning.
	skipDirs := map[string]bool{
		".git": true, "__pycache__": true,
		".cache": true, "proc": true, "sys": true, "dev": true,
		"run": true, "tmp": true, ".hg": true, ".svn": true,
		".pytest_cache": true, ".tox": true, ".mypy_cache": true,
		".ruff_cache": true,
	}
	// NOTE: .venv is NOT skipped — it's a valid Python virtualenv.
	// NOTE: ``node_modules`` used to be in skipDirs for years because
	// no plugin knew what to do with it; Sprint-17 added the npm
	// plugin which claims-and-terminals node_modules on Match.  The
	// walker visits the directory, the npm plugin queues an
	// Environment + returns Terminal=true, no further descent
	// happens.  Net walker-visit cost is one stat per node_modules
	// directory (not per-file), so the performance difference is
	// negligible even on dev laptops with hundreds of them.
	//
	// Side-effect: a venv pathologically planted inside a
	// node_modules directory (``node_modules/pyvenv.cfg``) is now
	// visible to the venv MarkerScanner.  That's technically new
	// behaviour but matches the semantic truth of the filesystem —
	// if a venv is there, we should surface it.  TestScannerSkipDirs
	// asserts ``.git`` + ``__pycache__`` stay blocked; it no longer
	// asserts node_modules does.

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
		if currentDepth > r.cfg.MaxDepth {
			return nil
		}

		base := filepath.Base(path)
		if skipDirs[base] {
			return nil
		}
		if skipAbsPaths[path] {
			return nil
		}

		// Offer this directory to every registered MarkerScanner.
		// Matches queue an Environment; warnings are surfaced as ScanErrors;
		// any Terminal=true vote stops descent into path.
		terminal := false
		for _, m := range markers {
			res := m.Match(path, base)
			if res.Warning != nil {
				errs = append(errs, *res.Warning)
			}
			if res.Matched {
				key := resolveKey(res.Env.Path)
				if !seen[key] {
					seen[key] = true
					envs = append(envs, res.Env)
				}
			}
			if res.Terminal {
				terminal = true
			}
		}
		if terminal {
			return nil
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

	_ = walk(r.cfg.ScanRoot)

	// Scan well-known version manager directories (pyenv, asdf) that may be
	// too deep for the main walk to reach.
	//
	// When the scan root is "/" (full system scan), also check the real user
	// home directories via userHomeDirs(). When the scan root is a specific
	// directory (e.g., /opt/app or a test temp dir), only check directories
	// under the scan root — never escape to unrelated system paths.
	var extraHomes []string
	cleanRoot := filepath.Clean(r.cfg.ScanRoot)
	if cleanRoot == "/" || (runtime.GOOS == "windows" && len(cleanRoot) <= 3) {
		extraHomes = userHomeDirs()
	}
	// Check directories directly under the scan root for version manager
	// patterns (handles cases where scan root is /home/user or similar).
	if topEntries, err := os.ReadDir(r.cfg.ScanRoot); err == nil {
		for _, e := range topEntries {
			if e.IsDir() {
				extraHomes = append(extraHomes, filepath.Join(r.cfg.ScanRoot, e.Name()))
			}
		}
	}
	// Also check the scan root itself.
	extraHomes = append(extraHomes, r.cfg.ScanRoot)
	// Walk each extra root with its own depth budget. We set rootDepth to the
	// depth of the extra root itself so that MaxDepth is measured from the
	// extra root, not from r.cfg.ScanRoot. Version manager directories like
	// .pyenv/versions/3.12.0/lib/python3.12/site-packages are 4+ levels deep,
	// so we use a minimum effective MaxDepth of 8 for extra roots regardless
	// of the configured MaxDepth — the caller's shallow MaxDepth is intended
	// to limit the main walk, not these explicit well-known paths.
	mainRootDepth := rootDepth
	savedMaxDepth := r.cfg.MaxDepth
	if r.cfg.MaxDepth < 8 {
		r.cfg.MaxDepth = 8
	}
	for _, home := range extraHomes {
		for _, extra := range extraScanRoots(home) {
			rootDepth = strings.Count(filepath.Clean(extra), string(os.PathSeparator))
			_ = walk(extra)
		}
	}
	rootDepth = mainRootDepth
	r.cfg.MaxDepth = savedMaxDepth

	// Invoke every RootScanner.  System-database scanners (dpkg, rpm)
	// gate themselves on a full-system scan inside DiscoverAll to avoid
	// polluting a scoped tempdir run with host-wide packages.  The
	// Windows-registry scanner fires unconditionally — registry lookup
	// is cheap and its results are tagged with real site-packages paths
	// under InstallPath, so a scoped scan still gets correct output.
	for _, rs := range rootScanners() {
		rEnvs, rErrs := rs.DiscoverAll(ctx)
		for _, env := range rEnvs {
			key := resolveKey(env.Path)
			if !seen[key] {
				seen[key] = true
				envs = append(envs, env)
			}
		}
		errs = append(errs, rErrs...)
	}

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
	// Check 1: pyvenv.cfg "home" key.  Use safeio — a hostile venv
	// might ship pyvenv.cfg as a symlink to /etc/shadow specifically
	// to poison the dangling-check's error message with file contents.
	if data, err := safeio.ReadFile(pyvenvCfgPath, maxPyvenvCfgSize); err == nil {
		scn := bufio.NewScanner(bytes.NewReader(data))
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
