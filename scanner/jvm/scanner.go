// Package jvm is the Sentari scanner plugin for the Java / JVM
// ecosystem.  It discovers and inventories every JAR / WAR / EAR /
// JMOD the agent can find across developer workstations (Maven +
// Gradle caches), JDK runtimes, the six major app servers (Tomcat,
// JBoss/WildFly, WebLogic, WebSphere, Jetty, GlassFish/Payara), and
// the generic /opt + /usr/share/java dumping grounds.  Uber-jar
// formats (Spring Boot, Quarkus, shaded) are traversed recursively
// to the plan's depth-3 cap so transitive dependencies surface as
// first-class records.
//
// The plugin registers itself with the scanner registry at init()
// time; ``agent/scanner/scanner.go`` discovers it via the same
// mechanism as every other ecosystem.  No explicit wiring is
// required in the orchestrator.
//
// ADRs 0002, 0003 and the Sprint-17 plan
// (docs/superpowers/plans/2026-04-23-jvm-scanner.md) explain the
// design decisions behind this package.
package jvm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func init() {
	scanner.Register(Scanner{})
}

// Layout tags carried on Environment.Name so Scan() can dispatch to
// the right walker without introducing separate env_types for every
// JVM discovery surface (the ecosystem string ``maven`` belongs in
// one place, but a Maven cache and a Tomcat install have different
// walk strategies).  Adding a new surface = new constant here +
// new case in Scan() + new ``discover*`` function.
const (
	layoutMavenCache  = "maven-cache"
	layoutGradleCache = "gradle-cache"
	layoutJDKRuntime  = "jdk-runtime"
	layoutTomcat      = "tomcat"
	layoutJBoss       = "jboss-wildfly"
	layoutWebLogic    = "weblogic"
	layoutWebSphere   = "websphere"
	layoutJetty       = "jetty"
	layoutGlassFish   = "glassfish-payara"
	layoutGeneric     = "generic-lib-dir"
)

// Scanner implements scanner.Scanner and scanner.RootScanner.  The
// zero value is usable — there is no per-scanner configuration, all
// environment variables are read at DiscoverAll / Scan time.
type Scanner struct{}

// EnvType reports the ecosystem this plugin represents on every
// PackageRecord it emits.  See ADR 0008 for the ``jvm`` vs
// ``maven`` vs ``java`` naming decision: the scanner identifier is
// ``jvm`` (what we're scanning), the server-side ecosystem string
// is ``maven`` (what OSV's schema calls it).  The mapping lives
// server-side; records emitted here carry EnvType=EnvJVM.
func (Scanner) EnvType() string { return EnvJVM }

// DiscoverAll fans out to every per-surface discoverer and merges
// their Environments.  Discoverers are pure and independent — adding
// a new one is literally one line added to the slice built below.
//
// Returned errors are currently always empty because each discoverer
// treats missing surfaces as "nothing to do" rather than an error;
// the signature matches RootScanner so future discoverers that
// produce diagnostic errors (permission denied on /var/lib/... etc.)
// can surface them without breaking the interface.
func (Scanner) DiscoverAll(ctx context.Context) ([]scanner.Environment, []scanner.ScanError) {
	_ = ctx // reserved for cancellation once discoverers do heavy IO
	var envs []scanner.Environment
	envs = append(envs, discoverMavenCache()...)
	envs = append(envs, discoverGradleCache()...)
	envs = append(envs, discoverJDK()...)
	envs = append(envs, discoverTomcat()...)
	envs = append(envs, discoverJBoss()...)
	envs = append(envs, discoverWebLogic()...)
	envs = append(envs, discoverWebSphere()...)
	envs = append(envs, discoverJetty()...)
	envs = append(envs, discoverGlassFish()...)

	// Generic runs LAST and receives the exclusion list of
	// already-emitted paths.  Generic lib-dir candidates that live
	// inside an app-server install tree (e.g. /opt/tomcat/lib under
	// an already-emitted /opt/tomcat) are skipped so JARs inside
	// specialised roots are scanned exactly once.
	alreadyCovered := make([]string, 0, len(envs))
	for _, e := range envs {
		alreadyCovered = append(alreadyCovered, e.Path)
	}
	envs = append(envs, discoverGeneric(alreadyCovered)...)
	return envs, nil
}

// Scan walks the given Environment and extracts every JAR it
// contains.  Dispatch is keyed on Environment.Name (the layout tag
// set by the discoverer that produced the Environment); unknown
// layouts produce a ScanError rather than silent nothing so wiring
// bugs are loud.
func (Scanner) Scan(ctx context.Context, env scanner.Environment) ([]scanner.PackageRecord, []scanner.ScanError) {
	_ = ctx // reserved for cancellation
	switch env.Name {
	case layoutMavenCache, layoutGradleCache,
		layoutTomcat, layoutJBoss, layoutWebLogic,
		layoutWebSphere, layoutJetty, layoutGlassFish,
		layoutGeneric:
		return scanDirTree(env.Path)
	case layoutJDKRuntime:
		return scanJDKRuntime(env.Path)
	default:
		return nil, []scanner.ScanError{{
			Path:      env.Path,
			EnvType:   EnvJVM,
			Error:     fmt.Sprintf("unknown jvm layout: %q", env.Name),
			Timestamp: time.Now().UTC(),
		}}
	}
}

// scanDirTree walks the given root recursively and invokes the JAR
// metadata extractor on every archive-named file it finds.  Errors
// (permission denied, broken symlinks, walk-level oddities) are
// collected into ScanError rather than propagated; one unreadable
// subdirectory must not stop the rest of the scan.
func scanDirTree(root string) ([]scanner.PackageRecord, []scanner.ScanError) {
	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)

	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:      path,
				EnvType:   EnvJVM,
				Error:     fmt.Sprintf("walk: %v", err),
				Timestamp: time.Now().UTC(),
			})
			// If the failure is on a directory, skip it.  For a file,
			// just move on; WalkDir will keep going either way.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !isJARLike(d.Name()) {
			return nil
		}
		// Oversize guard — avoid opening a 10 GB "fake JAR" into
		// archive/zip and letting it chew memory.  Matches the
		// maxJARBytes invariant enforced inside extractFromJar's
		// own paths.
		info, statErr := d.Info()
		if statErr == nil && info.Size() > int64(maxJARBytes) {
			errs = append(errs, scanner.ScanError{
				Path:      path,
				EnvType:   EnvJVM,
				Error:     fmt.Sprintf("JAR exceeds size cap: %d > %d bytes; skipped", info.Size(), maxJARBytes),
				Timestamp: time.Now().UTC(),
			})
			return nil
		}
		recs, jarErrs := extractFromJar(path)
		records = append(records, recs...)
		// extractFromJar doesn't stamp ScanError.Timestamp itself so the
		// extractor stays pure/time-independent; we stamp at the caller
		// boundary where errors cross out of the scanner package.
		now := time.Now().UTC()
		for _, e := range jarErrs {
			if e.Timestamp.IsZero() {
				e.Timestamp = now
			}
			errs = append(errs, e)
		}
		return nil
	})
	if walkErr != nil {
		// Only happens if the root itself is unreadable; the per-entry
		// callback above already handled per-file failures.
		errs = append(errs, scanner.ScanError{
			Path:      root,
			EnvType:   EnvJVM,
			Error:     fmt.Sprintf("walk root: %v", walkErr),
			Timestamp: time.Now().UTC(),
		})
	}
	return records, errs
}

// userHome returns the user's home directory using the platform-
// appropriate env var.  Returns "" when no home can be determined
// (unusual on real deployments; happens in minimal CI containers).
// We deliberately don't fall back to ``os.UserHomeDir`` because that
// masks env-var mis-configuration behind a system lookup that might
// resolve the caller's UID to an unexpected home.
func userHome() string {
	if runtime.GOOS == "windows" {
		if up := os.Getenv("USERPROFILE"); up != "" {
			return up
		}
	}
	return os.Getenv("HOME")
}

// isDir returns true iff the path exists and names a directory.
// Wraps os.Stat so the discoverer call sites stay readable.
func isDir(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.IsDir()
}

// containsPath reports whether envs already contains an Environment
// whose Path equals candidate after canonicalisation.  Guards against
// double-discovery when two env-var paths resolve to the same directory
// via symlinks, differing casing on case-insensitive FSes, or trailing-
// slash variance (``$MAVEN_HOME/repository`` vs ``$HOME/.m2/repository``
// pointing at the same physical dir through a symlink is the motivating
// case).  Falls back to filepath.Clean when EvalSymlinks errors (e.g.
// path doesn't exist yet), which still catches the trailing-slash case.
func containsPath(envs []scanner.Environment, candidate string) bool {
	target := canonicalPath(candidate)
	for _, e := range envs {
		if canonicalPath(e.Path) == target {
			return true
		}
	}
	return false
}

// canonicalPath returns a canonical form of p for deduplication:
// EvalSymlinks when it succeeds, filepath.Clean as the fallback.
// Mirrors the scanner.resolveKey helper in the parent package but is
// reimplemented here because resolveKey is unexported.
func canonicalPath(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}
