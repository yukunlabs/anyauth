package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yukunlabs/anyauth/internal/agentregistry"
	"github.com/yukunlabs/anyauth/internal/clientregistry"
	"github.com/yukunlabs/anyauth/internal/delegation"
	"github.com/yukunlabs/anyauth/internal/jose"
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
	case "demo":
		demo(os.Args[2:])
	case "protect":
		protect(os.Args[2:])
	case "clients":
		clients(os.Args[2:])
	case "agents":
		agents(os.Args[2:])
	case "delegate":
		delegate(os.Args[2:])
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
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	cfg := localdev.Config{
		ProviderPort: *providerPort,
		DataDir:      *dataDir,
	}
	if err := localdev.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func demo(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
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
		DemoApps:     true,
	}
	if err := localdev.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func protect(args []string) {
	fs := flag.NewFlagSet("protect", flag.ExitOnError)
	providerPort := fs.Int("provider-port", 7100, "local AnyAuth provider port")
	protectPort := fs.Int("port", 7200, "protected proxy port")
	upstream := fs.String("upstream", "", "upstream app URL, for example http://127.0.0.1:3000")
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	requireDelegation := fs.Bool("require-delegation", false, "require agent delegation Bearer tokens instead of browser SSO")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "--upstream is required")
		os.Exit(2)
	}

	cfg := localdev.Config{
		ProviderPort:      *providerPort,
		ProtectPort:       *protectPort,
		ProtectUpstream:   *upstream,
		DataDir:           *dataDir,
		RequireDelegation: *requireDelegation,
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

func agents(args []string) {
	if len(args) < 1 {
		agentsUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "add":
		agentsAdd(args[1:])
	case "list":
		agentsList(args[1:])
	case "remove":
		agentsRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown agents command: %s\n\n", args[0])
		agentsUsage()
		os.Exit(2)
	}
}

func agentsAdd(args []string) {
	fs := flag.NewFlagSet("agents add", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	id := fs.String("id", "", "agent id")
	name := fs.String("name", "", "agent display name")
	kind := fs.String("kind", "cli", "agent kind")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	agent, err := agentregistry.Add(*dataDir, agentregistry.Agent{
		ID:   *id,
		Name: *name,
		Kind: *kind,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Added agent %q\n", agent.ID)
	fmt.Printf("Name: %s\n", agent.Name)
	fmt.Printf("Kind: %s\n", agent.Kind)
}

func agentsList(args []string) {
	fs := flag.NewFlagSet("agents list", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	agents, err := agentregistry.Load(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	switch *format {
	case "json":
		raw, err := json.MarshalIndent(agents, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(raw))
	case "table":
		if len(agents) == 0 {
			fmt.Println("No agents registered.")
			return
		}
		for _, agent := range agents {
			status := "active"
			if agent.Disabled {
				status = "disabled"
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", agent.ID, agent.Name, agent.Kind, status)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
}

func agentsRemove(args []string) {
	fs := flag.NewFlagSet("agents remove", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	id := fs.String("id", "", "agent id")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *id == "" {
		fmt.Fprintln(os.Stderr, "--id is required")
		os.Exit(2)
	}

	agent, err := agentregistry.Remove(*dataDir, *id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Removed agent %q\n", agent.ID)
}

func delegate(args []string) {
	if len(args) < 1 {
		delegateUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "create":
		delegateCreate(args[1:])
	case "list":
		delegateList(args[1:])
	case "revoke":
		delegateRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown delegate command: %s\n\n", args[0])
		delegateUsage()
		os.Exit(2)
	}
}

func delegateCreate(args []string) {
	fs := flag.NewFlagSet("delegate create", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	agentID := fs.String("agent", "", "registered agent id")
	providerPort := fs.Int("provider-port", 7100, "local AnyAuth provider port used for issuer")
	protectPort := fs.Int("protect-port", 7200, "protected proxy port used for default audience")
	issuer := fs.String("issuer", "", "issuer override; defaults to provider port")
	audience := fs.String("audience", "", "audience override; defaults to protected proxy id")
	ttl := fs.Duration("ttl", 30*time.Minute, "delegation token lifetime")
	note := fs.String("note", "", "optional local note for this delegation")
	format := fs.String("format", "text", "output format: text, json, or token")
	pin := fs.String("pin", "", "PIN value; prefer --pin-stdin to avoid shell history")
	pinStdin := fs.Bool("pin-stdin", false, "read PIN from the first line of stdin")
	var scopes repeatString
	fs.Var(&scopes, "scope", "delegation scope; repeat for multiple values")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *agentID == "" {
		fmt.Fprintln(os.Stderr, "--agent is required")
		os.Exit(2)
	}
	if len(scopes) == 0 {
		scopes = repeatString{"app.read"}
	}
	if *issuer == "" {
		*issuer = delegation.IssuerForProviderPort(*providerPort)
	}
	if *audience == "" {
		*audience = delegation.AudienceForProtectPort(*protectPort)
	}

	agents, err := agentregistry.Load(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	agent, ok := agentregistry.Find(agents, *agentID)
	if !ok {
		fmt.Fprintf(os.Stderr, "agent %q not found\n", *agentID)
		os.Exit(1)
	}
	if agent.Disabled {
		fmt.Fprintf(os.Stderr, "agent %q is disabled\n", *agentID)
		os.Exit(1)
	}

	profile, err := userstore.Load(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := verifyPINIfConfigured(profile, *pin, *pinStdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	key, err := jose.LoadOrCreateRSAKey(filepath.Join(*dataDir, "dev-private-key.pem"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	record, token, err := delegation.Create(*dataDir, delegation.CreateRequest{
		Issuer:   *issuer,
		Audience: *audience,
		Human:    profile,
		Agent:    agent,
		Scopes:   scopes,
		Note:     *note,
		TTL:      *ttl,
		Key:      key,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	switch *format {
	case "token":
		fmt.Println(token)
	case "json":
		output := struct {
			Delegation delegation.Delegation `json:"delegation"`
			Token      string                `json:"token"`
		}{Delegation: record, Token: token}
		raw, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(raw))
	case "text":
		fmt.Printf("Created delegation %q\n", record.ID)
		fmt.Printf("Agent: %s (%s)\n", record.AgentName, record.AgentID)
		fmt.Printf("Human: %s <%s>\n", record.HumanName, record.HumanEmail)
		fmt.Printf("Audience: %s\n", record.Audience)
		fmt.Printf("Scopes: %s\n", strings.Join(record.Scopes, " "))
		fmt.Printf("Expires: %s\n", record.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Token: %s\n", token)
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
}

func delegateList(args []string) {
	fs := flag.NewFlagSet("delegate list", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	delegations, err := delegation.Load(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	switch *format {
	case "json":
		raw, err := json.MarshalIndent(delegations, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(raw))
	case "table":
		if len(delegations) == 0 {
			fmt.Println("No delegations created.")
			return
		}
		now := time.Now()
		for _, record := range delegations {
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n",
				record.ID,
				record.AgentID,
				record.Audience,
				strings.Join(record.Scopes, " "),
				delegationStatus(record, now),
				record.ExpiresAt.Format(time.RFC3339),
			)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
}

func delegateRevoke(args []string) {
	fs := flag.NewFlagSet("delegate revoke", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	id := fs.String("id", "", "delegation id")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *id == "" {
		fmt.Fprintln(os.Stderr, "--id is required")
		os.Exit(2)
	}

	record, err := delegation.Revoke(*dataDir, *id, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Revoked delegation %q\n", record.ID)
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
	case "clear-pin":
		userClearPIN(args[1:])
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

func userClearPIN(args []string) {
	fs := flag.NewFlagSet("user clear-pin", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	profile, err := userstore.ClearPIN(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("PIN cleared for %s <%s>\n", profile.Name, profile.Email)
}

func verifyPINIfConfigured(profile userstore.Profile, pin string, pinStdin bool) error {
	if !userstore.HasPIN(profile) {
		return nil
	}

	value := pin
	if pinStdin {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return fmt.Errorf("no PIN read from stdin")
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		value = strings.TrimSpace(scanner.Text())
	}
	if value == "" {
		return fmt.Errorf("PIN is configured; use --pin-stdin or --pin")
	}
	ok, err := userstore.VerifyPIN(profile, value)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("PIN verification failed")
	}
	return nil
}

func delegationStatus(record delegation.Delegation, now time.Time) string {
	if record.RevokedAt != nil {
		return "revoked"
	}
	if !now.Before(record.ExpiresAt) {
		return "expired"
	}
	return "active"
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
  anyauth demo [flags]
  anyauth protect --upstream <url> [flags]
  anyauth clients add --id <id> --redirect-uri <uri> [flags]
  anyauth clients list [flags]
  anyauth agents add --id <id> --name <name> [flags]
  anyauth agents list [flags]
  anyauth delegate create --agent <id> [flags]
  anyauth delegate list [flags]
  anyauth user show [flags]
  anyauth user set-pin [flags]
  anyauth user clear-pin [flags]
  anyauth version

Examples:
  go run ./cmd/anyauth serve
  go run ./cmd/anyauth demo
  go run ./cmd/anyauth protect --upstream http://127.0.0.1:3000
  go run ./cmd/anyauth serve -provider-port 7700
  go run ./cmd/anyauth clients add --id my-app --name "My App" --redirect-uri http://127.0.0.1:3000/callback
  go run ./cmd/anyauth clients list
  go run ./cmd/anyauth agents add --id codex --name "Codex Local Agent"
  go run ./cmd/anyauth delegate create --agent codex --scope app.read --format token
  printf "123456\n" | go run ./cmd/anyauth user set-pin --pin-stdin
  go run ./cmd/anyauth user clear-pin

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

func agentsUsage() {
	fmt.Print(`Manage local AnyAuth agents.

Usage:
  anyauth agents add --id <id> --name <name> [flags]
  anyauth agents list [flags]
  anyauth agents remove --id <id> [flags]

Examples:
  anyauth agents add --id codex --name "Codex Local Agent"
  anyauth agents list
  anyauth agents list --format json
  anyauth agents remove --id codex

`)
}

func delegateUsage() {
	fmt.Print(`Manage local AnyAuth agent delegations.

Usage:
  anyauth delegate create --agent <id> [flags]
  anyauth delegate list [flags]
  anyauth delegate revoke --id <id> [flags]

Examples:
  anyauth delegate create --agent codex --scope app.read
  anyauth delegate create --agent codex --scope app.read --format token
  anyauth delegate list
  anyauth delegate revoke --id del_...

`)
}

func userUsage() {
	fmt.Print(`Manage the local AnyAuth user.

Usage:
  anyauth user show [flags]
  anyauth user set-pin [flags]
  anyauth user clear-pin [flags]

Examples:
  anyauth user show
  printf "123456\n" | anyauth user set-pin --pin-stdin
  anyauth user clear-pin

`)
}
