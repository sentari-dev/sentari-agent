// Package secureperm restricts filesystem permissions on the agent's secret
// material (device private key, certificate bundle, data directory) to the
// owning service account only.
//
// On POSIX the agent already writes these with 0600/0700 mode bits, so the
// helpers here merely re-assert them.  On Windows mode bits are ignored by the
// filesystem entirely — a file written with os.WriteFile(..., 0600) is
// readable by every local user via the inherited ACL.  HardenFile/HardenDir
// replace the object's DACL with an explicit, inheritance-protected ACL that
// grants access only to LocalSystem, the Builtin Administrators group, and the
// current process user.  This closes the "device.key world-readable on
// Windows" gap for the mTLS identity that authenticates the agent to the
// server.
package secureperm

// HardenFile restricts a single file to the owning service account.
// Best-effort by contract: callers may log but should not treat a failure as
// fatal, since the agent's broader security posture (mTLS, short-lived certs)
// does not collapse on a single ACL miss.
func HardenFile(path string) error { return restrict(path, false) }

// HardenDir restricts a directory to the owning service account.  On Windows
// the applied DACL is inheritable, so files created under the directory after
// this call inherit the restriction.
func HardenDir(path string) error { return restrict(path, true) }
