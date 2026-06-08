package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/yukunlabs/anyauth/internal/clientregistry"
	"github.com/yukunlabs/anyauth/internal/localdev"
	"github.com/yukunlabs/anyauth/internal/userstore"
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
	case "user":
		user(os.Args[2:])
	case "version":
		fmt.Println("anyauth 0.3.0-dev")
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

func user(args []string) {
	if len(args) < 1 {
		userUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "show":
		userShow(args[1:])
	case "set-pin":
		userSetPIN(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown user command: %s\n\n", args[0])
		userUsage()
		os.Exit(2)
	}
}

func userShow(args []string) {
	fs := flag.NewFlagSet("user show", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	profile, err := userstore.Load(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	output := struct {
		Sub           string `json:"sub"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		PINConfigured bool   `json:"pin_configured"`
	}{
		Sub:           profile.Sub,
		Name:          profile.Name,
		Email:         profile.Email,
		PINConfigured: userstore.HasPIN(profile),
	}

	switch *format {
	case "json":
		raw, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(raw))
	case "table":
		fmt.Printf("Sub: %s\n", output.Sub)
		fmt.Printf("Name: %s\n", output.Name)
		fmt.Printf("Email: %s\n", output.Email)
		fmt.Printf("PIN configured: %t\n", output.PINConfigured)
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
}

func userSetPIN(args []string) {
	fs := flag.NewFlagSet("user set-pin", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	pin := fs.String("pin", "", "PIN value; prefer --pin-stdin to avoid shell history")
	pinStdin := fs.Bool("pin-stdin", false, "read PIN from the first line of stdin")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	value := *pin
	if *pinStdin {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			fmt.Fprintln(os.Stderr, "no PIN read from stdin")
			os.Exit(1)
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		value = strings.TrimSpace(scanner.Text())
	}
	if value == "" {
		fmt.Fprintln(os.Stderr, "PIN is required; use --pin-stdin or --pin")
		os.Exit(2)
	}

	profile, err := userstore.SetPIN(*dataDir, value)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("PIN configured for %s <%s>\n", profile.Name, profile.Email)
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
  anyauth user show [flags]
  anyauth user set-pin [flags]
  anyauth version

Examples:
  go run ./cmd/anyauth serve
  go run ./cmd/anyauth serve -provider-port 7700
  go run ./cmd/anyauth clients add --id my-app --name "My App" --redirect-uri http://127.0.0.1:3000/callback
  go run ./cmd/anyauth clients list
  printf "123456\n" | go run ./cmd/anyauth user set-pin --pin-stdin

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

func userUsage() {
	fmt.Print(`Manage the local AnyAuth user.

Usage:
  anyauth user show [flags]
  anyauth user set-pin [flags]

Examples:
  anyauth user show
  printf "123456\n" | anyauth user set-pin --pin-stdin

`)
}
