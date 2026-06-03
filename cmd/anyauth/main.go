package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yukunlabs/anyauth/internal/localdev"
)

func main() {
	if len(os.Args) < 2 {
		serve(os.Args[1:])
		return
	}

	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "version":
		fmt.Println("anyauth 0.1.0")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	providerPort := fs.Int("provider-port", 7100, "local AnyAuth provider port")
	appAPort := fs.Int("app-a-port", 7101, "demo app A port")
	appBPort := fs.Int("app-b-port", 7102, "demo app B port")
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	cfg := localdev.Config{
		ProviderPort: *providerPort,
		AppAPort:     *appAPort,
		AppBPort:     *appBPort,
		DataDir:      *dataDir,
	}
	if err := localdev.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`AnyAuth local-first authentication hub.

Usage:
  anyauth serve [flags]
  anyauth version

Examples:
  go run ./cmd/anyauth serve
  go run ./cmd/anyauth serve -provider-port 7700

`)
}
