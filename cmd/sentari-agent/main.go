//go:build !enterprise

// Community build of the sentari-agent CLI.
//
// Runs a one-shot scan of the local host, formats the result, and
// exits.  No server, no mTLS, no scheduling — the enterprise build
// (main_enterprise.go) adds those on top.  Per the 2026-04-24
// roadmap decision, every feature in this build is also available
// in the enterprise build; the split is additive, not divergent.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/sentari-dev/sentari-agent/config"
	"github.com/sentari-dev/sentari-agent/scanner"
	// Blank imports: pull in plugin packages so their init()
	// registers with scanner's registry at binary startup.  The
	// existing Python scanners (pip, conda, poetry, …) live
	// inside the scanner package itself so they're registered by
	// importing scanner.  Subpackages (scanner/jvm, scanner/aiagents,
	// etc.) must be imported here.
	_ "github.com/sentari-dev/sentari-agent/scanner/aiagents"
	_ "github.com/sentari-dev/sentari-agent/scanner/jvm"
)

func main() {
	// Flag definitions.
	//
	// Output format default note: when writing to stdout we want a
	// human-friendly summary by default (developer-first); when
	// writing to a file (``--output``) we default to JSON because
	// the most common use case is piping into a script or SIEM.
	// Either default can be overridden with ``--format``.
	scanFlag := flag.Bool("scan", false, "Run a scan of every supported ecosystem on this host")
	outputFlag := flag.String("output", "", "Output file path (default: stdout)")
	formatFlag := flag.String("format", "",
		"Output format: pretty | explain | json | csv  (default: pretty on stdout, json to --output)")
	explainFlag := flag.Bool("explain", false,
		"Shorthand for --format=explain; verbose human-readable scan report with "+
			"recent-install and AI-agent highlights")
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

	os.Exit(runOneShot(context.Background(), cfg, oneShotOptions{
		outputPath: *outputFlag,
		format:     *formatFlag,
		explain:    *explainFlag,
	}))
}
