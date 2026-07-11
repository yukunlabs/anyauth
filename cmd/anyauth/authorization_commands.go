package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yukunlabs/anyauth/internal/auditlog"
	"github.com/yukunlabs/anyauth/internal/authz"
	"github.com/yukunlabs/anyauth/internal/authzstore"
	"github.com/yukunlabs/anyauth/internal/userstore"
)

func applications(args []string) {
	if len(args) < 1 {
		applicationsUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		applicationsAdd(args[1:])
	case "list":
		applicationsList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown applications command: %s\n\n", args[0])
		applicationsUsage()
		os.Exit(2)
	}
}

func applicationsAdd(args []string) {
	fs := flag.NewFlagSet("applications add", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	id := fs.String("id", "", "application id")
	name := fs.String("name", "", "application display name")
	var actions repeatString
	var resourceTypes repeatString
	fs.Var(&actions, "action", "semantic action; repeat for multiple actions")
	fs.Var(&resourceTypes, "resource-type", "resource type; repeat for multiple types")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	application, err := authzstore.New(*dataDir).AddApplication(authzstore.Application{
		ID:            *id,
		Name:          *name,
		Actions:       actions,
		ResourceTypes: resourceTypes,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Added application %q\n", application.ID)
	fmt.Printf("Name: %s\n", application.Name)
	fmt.Printf("Actions: %s\n", strings.Join(application.Actions, ", "))
	fmt.Printf("Resource types: %s\n", strings.Join(application.ResourceTypes, ", "))
}

func applicationsList(args []string) {
	fs := flag.NewFlagSet("applications list", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	state, err := authzstore.New(*dataDir).Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch *format {
	case "json":
		printJSON(state.Applications)
	case "table":
		if len(state.Applications) == 0 {
			fmt.Println("No authorization applications registered.")
			return
		}
		for _, application := range state.Applications {
			fmt.Printf("%s\t%s\t%s\t%s\n", application.ID, application.Name, strings.Join(application.Actions, ","), strings.Join(application.ResourceTypes, ","))
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
}

func authorization(args []string) {
	if len(args) < 1 {
		authorizationUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "request":
		authorizationRequest(args[1:])
	case "check":
		authorizationCheck(args[1:])
	case "requests":
		authorizationRequestsList(args[1:])
	case "grants":
		authorizationGrantsList(args[1:])
	case "revoke":
		authorizationRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown authz command: %s\n\n", args[0])
		authorizationUsage()
		os.Exit(2)
	}
}

func authorizationRequest(args []string) {
	fs := flag.NewFlagSet("authz request", flag.ExitOnError)
	providerURL := fs.String("provider-url", "http://127.0.0.1:7100", "running AnyAuth provider URL")
	agentID := fs.String("agent", "", "registered agent id")
	applicationID := fs.String("application", "", "authorization application id")
	action := fs.String("action", "", "semantic action")
	resourceType := fs.String("resource-type", "", "resource type")
	resourceID := fs.String("resource", "", "resource id")
	taskID := fs.String("task-id", "", "optional stable task id")
	taskName := fs.String("task", "", "optional task name")
	ttl := fs.Duration("ttl", 30*time.Minute, "requested grant lifetime")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	input := map[string]any{
		"agent_id":       *agentID,
		"application_id": *applicationID,
		"action":         *action,
		"resource_type":  *resourceType,
		"resource_id":    *resourceID,
		"task_id":        *taskID,
		"task_name":      *taskName,
		"ttl_seconds":    int64(*ttl / time.Second),
	}
	var output struct {
		Request     authzstore.AuthorizationRequest `json:"request"`
		ApprovalURL string                          `json:"approval_url"`
	}
	if err := postJSON(strings.TrimRight(*providerURL, "/")+"/api/authorization-requests", input, &output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch *format {
	case "json":
		printJSON(output)
	case "text":
		fmt.Printf("Created authorization request %q\n", output.Request.ID)
		fmt.Printf("Agent: %s\n", output.Request.Actor.ID)
		fmt.Printf("Permission: %s on %s:%s\n", output.Request.Permission.Action, output.Request.Permission.Resource.Type, output.Request.Permission.Resource.ID)
		fmt.Printf("Approve: %s\n", output.ApprovalURL)
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
}

func authorizationCheck(args []string) {
	fs := flag.NewFlagSet("authz check", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory used to resolve the default subject")
	providerURL := fs.String("provider-url", "http://127.0.0.1:7100", "running AnyAuth provider URL")
	agentID := fs.String("agent", "", "registered agent id")
	subjectID := fs.String("subject", "", "human subject; defaults to the local profile")
	applicationID := fs.String("application", "", "authorization application id")
	action := fs.String("action", "", "semantic action")
	resourceType := fs.String("resource-type", "", "resource type")
	resourceID := fs.String("resource", "", "resource id")
	taskID := fs.String("task-id", "", "optional task id")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *subjectID == "" {
		profile, err := userstore.Load(*dataDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		*subjectID = profile.Sub
	}
	request := authz.Request{
		Actor:         authz.Identity{Type: authz.IdentityAgent, ID: *agentID},
		Subject:       authz.Identity{Type: authz.IdentityHuman, ID: *subjectID},
		ApplicationID: *applicationID,
		Action:        authz.Action{Name: *action},
		Resource:      authz.Resource{Type: *resourceType, ID: *resourceID},
		Context:       authz.RequestContext{TaskID: *taskID},
	}
	var output struct {
		Decision bool `json:"decision"`
		Context  struct {
			DecisionID string           `json:"decision_id"`
			ReasonCode authz.ReasonCode `json:"reason_code"`
			Reason     string           `json:"reason"`
			GrantIDs   []string         `json:"grant_ids"`
		} `json:"context"`
	}
	if err := postJSON(strings.TrimRight(*providerURL, "/")+"/access/v1/evaluation", request, &output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch *format {
	case "json":
		printJSON(output)
	case "text":
		fmt.Printf("Decision: %t\n", output.Decision)
		fmt.Printf("Decision ID: %s\n", output.Context.DecisionID)
		fmt.Printf("Reason: %s (%s)\n", output.Context.Reason, output.Context.ReasonCode)
	default:
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
}

func authorizationRequestsList(args []string) {
	fs := flag.NewFlagSet("authz requests", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	state, err := authzstore.New(*dataDir).Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *format == "json" {
		printJSON(state.Requests)
		return
	}
	if *format != "table" {
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
	if len(state.Requests) == 0 {
		fmt.Println("No semantic authorization requests.")
		return
	}
	for _, request := range state.Requests {
		fmt.Printf("%s\t%s\t%s\t%s\t%s:%s\t%s\n", request.ID, request.StatusAt(time.Now()), request.Actor.ID, request.Permission.Action, request.Permission.Resource.Type, request.Permission.Resource.ID, request.TaskName)
	}
}

func authorizationGrantsList(args []string) {
	fs := flag.NewFlagSet("authz grants", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	state, err := authzstore.New(*dataDir).Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *format == "json" {
		printJSON(state.Grants)
		return
	}
	if *format != "table" {
		fmt.Fprintf(os.Stderr, "unknown format: %s\n", *format)
		os.Exit(2)
	}
	if len(state.Grants) == 0 {
		fmt.Println("No semantic authorization grants.")
		return
	}
	for _, grant := range state.Grants {
		status := "active"
		if grant.RevokedAt != nil {
			status = "revoked"
		} else if !time.Now().Before(grant.ExpiresAt) {
			status = "expired"
		}
		for _, permission := range grant.Permissions {
			fmt.Printf("%s\t%s\t%s\t%s\t%s:%s\t%s\n", grant.ID, status, grant.Grantee.ID, permission.Action, permission.Resource.Type, permission.Resource.ID, grant.ExpiresAt.Format(time.RFC3339))
		}
	}
}

func authorizationRevoke(args []string) {
	fs := flag.NewFlagSet("authz revoke", flag.ExitOnError)
	dataDir := fs.String("data-dir", ".anyauth", "local AnyAuth data directory")
	id := fs.String("id", "", "grant id")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	grant, err := authzstore.New(*dataDir).RevokeGrant(*id, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	permission := grant.Permissions[0]
	if _, err := auditlog.Append(*dataDir, auditlog.Event{
		Type:          "authorization.revoke",
		Decision:      "revoke",
		ActorType:     "human",
		HumanSub:      grant.Subject.ID,
		AgentID:       grant.Grantee.ID,
		ApplicationID: grant.ApplicationID,
		Action:        permission.Action,
		ResourceType:  permission.Resource.Type,
		Resource:      permission.Resource.ID,
		TaskID:        grant.TaskID,
		GrantIDs:      []string{grant.ID},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to append audit event: %v\n", err)
	}
	fmt.Printf("Revoked authorization grant %q\n", grant.ID)
}

func postJSON(target string, input any, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(target, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiError struct {
			Description string `json:"error_description"`
		}
		if json.Unmarshal(responseBody, &apiError) == nil && apiError.Description != "" {
			return fmt.Errorf("AnyAuth API returned %s: %s", resp.Status, apiError.Description)
		}
		return fmt.Errorf("AnyAuth API returned %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}
	if err := json.Unmarshal(responseBody, output); err != nil {
		return err
	}
	return nil
}

func printJSON(value any) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(raw))
}

func applicationsUsage() {
	fmt.Print(`Manage semantic authorization applications.

Usage:
  anyauth applications add --id <id> --action <action> --resource-type <type> [flags]
  anyauth applications list [flags]

`)
}

func authorizationUsage() {
	fmt.Print(`Manage semantic agent authorization.

Usage:
  anyauth authz request --agent <id> --application <id> --action <action> --resource-type <type> --resource <id> [flags]
  anyauth authz check --agent <id> --application <id> --action <action> --resource-type <type> --resource <id> [flags]
  anyauth authz requests [flags]
  anyauth authz grants [flags]
  anyauth authz revoke --id <grant-id> [flags]

`)
}
