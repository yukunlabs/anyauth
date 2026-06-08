package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/yukunlabs/anyauth/internal/clientregistry"
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
	case "clients":
		clients(os.Args[2:])
	case "version":
		fmt.Println("anyauth 0.2.0")
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

func clients(args []string) {
	if len(args) < 1 {
		clientsUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "add":
		clientsAdd(args[1:])
	case "list":
		clientsList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown clients command: %s\n\n", args[0])
		clientsUsage()
		os.Exit(2)
	}
}

func clientsAdd(args []string) {
	fs := flag.NewFlagSet("clients add", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	id := fs.String("id", "", "client id")
	name := fs.String("name", "", "client display name")
	secret := fs.String("secret", "", "client secret; generated when omitted")
	var redirectURIs repeatString
	fs.Var(&redirectURIs, "redirect-uri", "allowed redirect URI; repeat for multiple values")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	client, err := clientregistry.Add(*dataDir, clientregistry.Client{
		ID:           *id,
		Name:         *name,
		Secret:       *secret,
		RedirectURIs: redirectURIs,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Added client %q\n", client.ID)
	fmt.Printf("Name: %s\n", client.Name)
	fmt.Printf("Secret: %s\n", client.Secret)
	fmt.Println("Redirect URIs:")
	for _, redirectURI := range client.RedirectURIs {
		fmt.Printf("  - %s\n", redirectURI)
	}
}

func clientsList(args []string) {
	fs := flag.NewFlagSet("clients list", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	clients, err := clientregistry.Load(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	switch *format {
	case "json":
		raw, err := json.MarshalIndent(clients, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(raw))
	case "table":
		if len(clients) == 0 {
			fmt.Println("No clients registered.")
			return
		}
		for _, client := range clients {
			fmt.Printf("%s\t%s\t%s\n", client.ID, client.Name, strings.Join(client.RedirectURIs, ", "))
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
}

type repeatString []string

func (r *repeatString) String() string {
	return strings.Join(*r, ",")
}

func (r *repeatString) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func usage() {
	fmt.Print(`AnyAuth local-first authentication hub.

Usage:
  anyauth serve [flags]
  anyauth clients add --id <id> --redirect-uri <uri> [flags]
  anyauth clients list [flags]
  anyauth version

Examples:
  go run ./cmd/anyauth serve
  go run ./cmd/anyauth serve -provider-port 7700
  go run ./cmd/anyauth clients add --id my-app --name "My App" --redirect-uri http://127.0.0.1:3000/callback
  go run ./cmd/anyauth clients list

`)
}

func clientsUsage() {
	fmt.Print(`Manage local AnyAuth clients.

Usage:
  anyauth clients add --id <id> --redirect-uri <uri> [flags]
  anyauth clients list [flags]

Examples:
  anyauth clients add --id my-app --name "My App" --redirect-uri http://127.0.0.1:3000/callback
  anyauth clients list
  anyauth clients list --format json

`)
}
