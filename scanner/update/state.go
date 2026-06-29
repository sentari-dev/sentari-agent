package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// highWaterFile is the name of the persisted last-applied marker under
// the agent state dir.
const highWaterFile = "update_state.json"

// highWater records the last upgrade the agent actually applied.  It is
// the freshness anchor: a manifest whose version is <= Version, or
// whose served_at is older than ServedAt, is treated as a replay and
// refused.  Persisted as a small JSON file under the agent data dir.
type highWater struct {
	Version  string `json:"version"`
	ServedAt string `json:"served_at"`
}

// readHighWater loads the persisted marker from stateDir.  A missing
// file is not an error — it returns the zero value so a first-ever
// upgrade is allowed.
func readHighWater(stateDir string) (highWater, error) {
	if stateDir == "" {
		return highWater{}, nil
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, highWaterFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return highWater{}, nil
		}
		return highWater{}, fmt.Errorf("read update state: %w", err)
	}
	var hw highWater
	if err := json.Unmarshal(raw, &hw); err != nil {
		return highWater{}, fmt.Errorf("parse update state: %w", err)
	}
	return hw, nil
}

// writeHighWater persists the marker atomically (temp file + rename) so
// a crash mid-write cannot corrupt it.
func writeHighWater(stateDir string, hw highWater) error {
	if stateDir == "" {
		return errors.New("no state dir configured for update high-water mark")
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	raw, err := json.Marshal(hw)
	if err != nil {
		return fmt.Errorf("marshal update state: %w", err)
	}
	dst := filepath.Join(stateDir, highWaterFile)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write update state: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit update state: %w", err)
	}
	return nil
}

// checkFreshness refuses a manifest that is not strictly newer than the
// recorded high-water mark.  An empty stateDir disables the check (the
// caller logs a warning); a manifest is rejected as a replay when its
// version is <= the marker version, or (at the same version) its
// served_at is <= the marker served_at.
func checkFreshness(stateDir, version, servedAt string) error {
	hw, err := readHighWater(stateDir)
	if err != nil {
		return err
	}
	if hw.Version == "" {
		return nil // first upgrade — nothing to compare against
	}
	cmp, err := compareVersions(version, hw.Version)
	if err != nil {
		return fmt.Errorf("freshness: compare versions: %w", err)
	}
	if cmp < 0 {
		return fmt.Errorf("replay refused: manifest version %s is older than last-applied %s", version, hw.Version)
	}
	if cmp == 0 {
		// Same version: served_at must strictly advance.  Lexical
		// comparison is correct for RFC 3339 UTC timestamps (the server
		// stamps Z-suffixed times).  An empty served_at can never beat
		// a recorded one.
		if servedAt <= hw.ServedAt {
			return fmt.Errorf("replay refused: manifest served_at %q does not advance past last-applied %q at version %s", servedAt, hw.ServedAt, version)
		}
	}
	return nil
}
