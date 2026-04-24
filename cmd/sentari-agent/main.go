//go:build !enterprise

package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sentari-dev/sentari-agent/config"
	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/containers"
	// Blank import: pulls in the JVM plugin so its init()
	// registers with scanner's registry at binary startup.  The
	// existing Python scanners (pip, conda, poetry, …) live
	// inside the scanner package itself so they're registered by
	// importing scanner.  Subpackages (scanner/jvm, future
	// scanner/maven-alternatives, etc.) must be imported here.
	_ "github.com/sentari-dev/sentari-agent/scanner/jvm"
)

func main() {
	// Flag definitions
	scanFlag := flag.Bool("scan", false, "Run a scan of all supported ecosystems (Python + JVM)")
	outputFlag := flag.String("output", "", "Output file path (default: stdout)")
	formatFlag := flag.String("format", "json", "Output format: json or csv (default: json)")
	configFlag := flag.String("config", "", "Path to agent config file")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("sentari-agent %s\n", scanner.Version)
		os.Exit(0)
	}

	if !*scanFlag {
		flag.Usage()
		os.Exit(1)
	}

	// Load configuration: start with defaults, override from config file.
	agentCfg := config.DefaultConfig()
	if *configFlag != "" {
		var err error
		agentCfg, err = config.LoadFromFile(*configFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config %s: %v\n", *configFlag, err)
			os.Exit(1)
		}
	}

	// Map agent config to scanner config.
	cfg := scanner.Config{
		ScanRoot:       agentCfg.Scanner.ScanRoot,
		MaxDepth:       agentCfg.Scanner.MaxDepth,
		MaxWorkers:     8,
		ScanContainers: agentCfg.Scanner.ScanContainers,
	}
	// Allow SENTARI_SCAN_CONTAINERS=true to flip the flag at
	// runtime without touching the config file.  Common for "I
	// want to try this on one host first."
	if v := os.Getenv("SENTARI_SCAN_CONTAINERS"); v == "true" || v == "1" {
		cfg.ScanContainers = true
	}

	// Run the scan with a proper background context.
	ctx := context.Background()
	s := scanner.NewScanner(cfg)
	result, err := s.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}

	// Container-image scan phase.  Opt-in; the host scan above
	// runs unconditionally so operators always get baseline
	// inventory.  ScanAndAppend handles caps, per-target
	// timeouts, and panic recovery.
	if cfg.ScanContainers {
		containers.ScanAndAppend(ctx, cfg, result)
	}

	// Format output.
	var output []byte
	switch *formatFlag {
	case "csv":
		output, err = formatAsCSV(result)
	case "json":
		output, err = json.MarshalIndent(result, "", "  ")
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s\n", *formatFlag)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Formatting error: %v\n", err)
		os.Exit(1)
	}

	// Write output.
	if *outputFlag != "" {
		// Use 0600 — scan results may contain sensitive inventory data.
		err = os.WriteFile(*outputFlag, output, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Results written to %s (%d packages found)\n", *outputFlag, len(result.Packages))
	} else {
		fmt.Println(string(output))
	}
}

func formatAsCSV(result *scanner.ScanResult) ([]byte, error) {
	b := &bytes.Buffer{}
	w := csv.NewWriter(b)

	// Always write header, even for empty results.
	if err := w.Write([]string{
		"Name", "Version", "InstallPath", "EnvType", "InterpreterVersion",
		"InstallerUser", "InstallDate", "Environment",
	}); err != nil {
		return nil, err
	}

	for _, pkg := range result.Packages {
		if err := w.Write([]string{
			pkg.Name,
			pkg.Version,
			pkg.InstallPath,
			pkg.EnvType,
			pkg.InterpreterVersion,
			pkg.InstallerUser,
			pkg.InstallDate,
			pkg.Environment,
		}); err != nil {
			return nil, err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
