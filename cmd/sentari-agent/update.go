package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/config"
	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/update"
)

// updateMode describes which sub-action of `--update-*` to run.
type updateMode int

const (
	updateModeCheck    updateMode = iota // print plan, do not mutate
	updateModeApply                      // download, swap, restart
	updateModeRollback                   // restore .prev, restart
)

// runUpdate is the entry point for `--update-check / --update-apply /
// --update-rollback`.  Returns a process exit code; the caller's
// os.Exit lives in main.go so this function stays unit-testable.
//
// installPathOverride is "" by default, in which case the running
// binary's path (via os.Executable) is used.  Operators with an
// out-of-tree install can override.
func runUpdate(mode updateMode, agentCfg config.AgentConfig, serverURLOverride, dataDir, installPathOverride string) int {
	installPath, err := resolveInstallPath(installPathOverride)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not resolve install path: %v\n", err)
		return 1
	}

	// Rollback is independent of server / certs / trust — only needs
	// the on-disk .prev sibling.  Short-circuit before doing any
	// network setup so a fully air-gapped operator can recover from
	// a bad upgrade without the server being reachable.
	if mode == updateModeRollback {
		if err := update.Rollback(installPath); err != nil {
			fmt.Fprintf(os.Stderr, "Rollback failed: %v\n", err)
			return 1
		}
		fmt.Println("Rollback complete.")
		return 0
	}

	serverURL := agentCfg.Server.URL
	if serverURLOverride != "" {
		serverURL = serverURLOverride
	}
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "No server URL configured. Use --server-url or set [server] url in config file.")
		return 1
	}

	certDir := dataDir + "/certs"
	certFile := agentCfg.Server.CertFile
	keyFile := agentCfg.Server.KeyFile
	caFile := agentCfg.Server.CACertFile
	if certFile == "" {
		certFile = certDir + "/device.crt"
	}
	if keyFile == "" {
		keyFile = certDir + "/device.key"
	}
	if caFile == "" {
		caFile = certDir + "/ca.crt"
	}

	if !comms.CertsExist(certDir) {
		fmt.Fprintln(os.Stderr, "Agent is not registered (no client certificates on disk). Run --upload or --serve first.")
		return 1
	}

	trust, err := comms.LoadInstallGateTrust(certDir)
	if err != nil || trust == nil {
		fmt.Fprintln(os.Stderr, "Install-gate trust is not provisioned. Re-register the agent (--upload) to learn the pubkey.")
		return 1
	}
	rawPub, err := base64.StdEncoding.DecodeString(trust.PubKeyB64)
	if err != nil || len(rawPub) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "Install-gate pubkey on disk is corrupt; re-register the agent.")
		return 1
	}

	mtlsClient, err := comms.NewClient(comms.ClientConfig{
		ServerURL:  serverURL,
		CertFile:   certFile,
		KeyFile:    keyFile,
		CACertFile: caFile,
		Timeout:    60 * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mTLS client init failed: %v\n", err)
		return 1
	}

	client := &update.Client{
		// comms.Client wraps an *http.Client.  The update package
		// only needs the underlying client.  Defensive cast: the
		// existing exported helper is HTTPClient().
		HTTPClient:  mtlsClient.HTTPClient(),
		ServerURL:   serverURL,
		TrustedKeys: map[string]ed25519.PublicKey{trust.KeyID: ed25519.PublicKey(rawPub)},
		CurrentVer:  scanner.Version,
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
	}

	plan, err := client.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update check failed: %v\n", err)
		return 1
	}

	switch mode {
	case updateModeCheck:
		printPlan(plan)
		return 0
	case updateModeApply:
		printPlan(plan)
		if !plan.UpgradeAvailable {
			fmt.Println("No upgrade available — nothing to do.")
			return 0
		}
		stagedDir := filepath.Join(dataDir, "staged")
		if err := client.Apply(plan, installPath, stagedDir); err != nil {
			fmt.Fprintf(os.Stderr, "Apply failed: %v\n", err)
			// Even on apply error after binary swap, surface non-zero so
			// the caller knows manual intervention may be needed.
			return 1
		}
		fmt.Printf("Upgraded to %s — service restarted.\n", plan.LatestVersion)
		return 0
	}
	return 1
}

func resolveInstallPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	// os.Executable returns the path the current process was started
	// from — exactly the binary we want to upgrade in place.
	return os.Executable()
}

func printPlan(plan *update.Plan) {
	fmt.Printf("Platform:   %s\n", plan.PlatformKey)
	fmt.Printf("Current:    %s\n", or(plan.CurrentVersion, "<unknown>"))
	fmt.Printf("Latest:     %s\n", or(plan.LatestVersion, "<none available>"))
	if plan.UpgradeAvailable {
		fmt.Printf("Action:     run with --update-apply to upgrade (size: %d bytes)\n", plan.Platform.SizeBytes)
	} else if plan.LatestVersion != "" {
		fmt.Println("Action:     up to date")
	} else {
		fmt.Println("Action:     no release advertised by server for this platform")
	}
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
