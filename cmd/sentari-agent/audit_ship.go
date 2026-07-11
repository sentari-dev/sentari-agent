//go:build enterprise

package main

import (
	"context"
	"log/slog"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/comms"
)

// auditShipBatch is the number of unshipped audit rows fetched into memory per
// drain iteration.  It matches the server-enforced per-request cap so a full
// batch is shipped in a single ShipAudit call.  A var (not a const) purely so
// tests can shrink it to exercise multi-iteration draining.
var auditShipBatch = comms.AuditShipMaxBatch

// shipAuditLog drains the agent's un-shipped local audit entries to the
// server's re-anchoring endpoint in bounded batches, marking each successful
// batch as shipped before fetching the next.  Fetching a batch at a time (via
// UnshippedEntries(auditShipBatch)) keeps peak memory proportional to the batch
// size, not to the offline duration: a 365-day air-gap backlog of tens of
// thousands of rows drains over several iterations without one giant
// allocation.  Best-effort: on the first transport/auth failure it stops,
// leaving the remaining entries queued for the next cycle.
func shipAuditLog(ctx context.Context, client *comms.Client, auditLog *audit.AuditLog, deviceID string, log *slog.Logger) {
	if deviceID == "" {
		return
	}
	shipped := 0
	for {
		entries, err := auditLog.UnshippedEntries(auditShipBatch)
		if err != nil {
			log.Warn("audit ship: failed to read unshipped entries", slog.String("err", err.Error()))
			break
		}
		if len(entries) == 0 {
			break
		}
		maxID, shipErr := client.ShipAudit(ctx, deviceID, entries)
		if shipErr != nil {
			log.Warn("audit ship failed", slog.String("err", shipErr.Error()))
			break
		}
		if markErr := auditLog.MarkShipped(maxID); markErr != nil {
			log.Warn("audit ship: failed to mark entries shipped", slog.String("err", markErr.Error()))
			break
		}
		shipped += len(entries)
		// A short read means the backlog is drained; MarkShipped advanced the
		// shipped cursor so the next fetch would otherwise re-query needlessly.
		if len(entries) < auditShipBatch {
			break
		}
	}
	if shipped > 0 {
		log.Info("audit log re-anchored to server", slog.Int("entries", shipped))
	}
}
