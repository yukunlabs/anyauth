package localdev

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yukunlabs/anyauth/internal/agentregistry"
	"github.com/yukunlabs/anyauth/internal/auditlog"
	"github.com/yukunlabs/anyauth/internal/clientregistry"
	"github.com/yukunlabs/anyauth/internal/delegation"
	"github.com/yukunlabs/anyauth/internal/jose"
	"github.com/yukunlabs/anyauth/internal/policy"
	"github.com/yukunlabs/anyauth/internal/userstore"
)

func TestLocalSSOFlow(t *testing.T) {
	cfg := Config{
		ProviderPort: freePort(t),
		AppAPort:     freePort(t),
		AppBPort:     freePort(t),
		DataDir:      t.TempDir(),
		DemoApps:     true,
	}
	_, err := clientregistry.Add(cfg.DataDir, clientregistry.Client{
		ID:           "custom-app",
		Name:         "Custom App",
		Secret:       "custom-secret",
		RedirectURIs: []string{"http://127.0.0.1:18080/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}

	servers, cfg, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := servers.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
	}()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	provider := "http://127.0.0.1:" + itoa(cfg.ProviderPort)
	appA := "http://127.0.0.1:" + itoa(cfg.AppAPort)
	appB := "http://127.0.0.1:" + itoa(cfg.AppBPort)

	body := mustGetBody(t, client, provider+"/.well-known/openid-configuration", http.StatusOK)
	if !strings.Contains(body, `"issuer":"`+provider+`"`) {
		t.Fatalf("discovery issuer missing from %s", body)
	}
	body = mustGetBody(t, client, provider+"/jwks.json", http.StatusOK)
	if !strings.Contains(body, `"alg":"RS256"`) {
		t.Fatalf("JWKS RS256 key missing from %s", body)
	}
	customAuthorize := provider + "/authorize?" + url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{"custom-app"},
		"redirect_uri":          []string{"http://127.0.0.1:18080/callback"},
		"scope":                 []string{"openid profile email"},
		"state":                 []string{"custom-state"},
		"nonce":                 []string{"custom-nonce"},
		"code_challenge":        []string{"custom-challenge"},
		"code_challenge_method": []string{"S256"},
	}.Encode()
	body = mustGetBody(t, client, customAuthorize, http.StatusOK)
	if !strings.Contains(body, "Sign in with AnyAuth") {
		t.Fatalf("expected custom client to reach login page, got %s", body)
	}

	authorizeURL := mustGetLocation(t, client, appA+"/login")
	body = mustGetBody(t, client, authorizeURL, http.StatusOK)
	if !strings.Contains(body, "Sign in with AnyAuth") {
		t.Fatalf("expected login page, got %s", body)
	}

	parsedAuthorize, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	callbackA := mustPostLocation(t, client, provider+"/login", parsedAuthorize.Query())
	if !strings.HasPrefix(callbackA, appA+"/callback?") {
		t.Fatalf("callbackA = %s", callbackA)
	}
	if loc := mustGetLocation(t, client, callbackA); loc != "/" {
		t.Fatalf("callback App A redirect = %s, want /", loc)
	}
	body = mustGetBody(t, client, appA+"/", http.StatusOK)
	if !strings.Contains(body, "Logged in through AnyAuth") || !strings.Contains(body, "local.user@anyauth.local") {
		t.Fatalf("App A did not show logged in user: %s", body)
	}

	authorizeURL = mustGetLocation(t, client, appB+"/login")
	callbackB := mustGetLocation(t, client, authorizeURL)
	if !strings.HasPrefix(callbackB, appB+"/callback?") {
		t.Fatalf("expected provider session reuse, got %s", callbackB)
	}
	if loc := mustGetLocation(t, client, callbackB); loc != "/" {
		t.Fatalf("callback App B redirect = %s, want /", loc)
	}
	body = mustGetBody(t, client, appB+"/", http.StatusOK)
	if !strings.Contains(body, "Logged in through AnyAuth") || !strings.Contains(body, "local.user@anyauth.local") {
		t.Fatalf("App B did not show logged in user: %s", body)
	}
}

func TestLocalSSOFlowWithPIN(t *testing.T) {
	cfg := Config{
		ProviderPort: freePort(t),
		AppAPort:     freePort(t),
		AppBPort:     freePort(t),
		DataDir:      t.TempDir(),
		DemoApps:     true,
	}
	if _, err := userstore.SetPIN(cfg.DataDir, "123456"); err != nil {
		t.Fatal(err)
	}

	servers, cfg, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := servers.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
	}()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	provider := "http://127.0.0.1:" + itoa(cfg.ProviderPort)
	appA := "http://127.0.0.1:" + itoa(cfg.AppAPort)

	authorizeURL := mustGetLocation(t, client, appA+"/login")
	body := mustGetBody(t, client, authorizeURL, http.StatusOK)
	if !strings.Contains(body, `name="pin"`) {
		t.Fatalf("expected PIN input, got %s", body)
	}

	parsedAuthorize, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	values := parsedAuthorize.Query()
	values.Set("pin", "000000")
	body = mustPostBody(t, client, provider+"/login", values, http.StatusUnauthorized)
	if !strings.Contains(body, "PIN verification failed") {
		t.Fatalf("expected PIN failure, got %s", body)
	}

	values.Set("pin", "123456")
	callbackA := mustPostLocation(t, client, provider+"/login", values)
	if !strings.HasPrefix(callbackA, appA+"/callback?") {
		t.Fatalf("callbackA = %s", callbackA)
	}
	if loc := mustGetLocation(t, client, callbackA); loc != "/" {
		t.Fatalf("callback App A redirect = %s, want /", loc)
	}
	body = mustGetBody(t, client, appA+"/", http.StatusOK)
	if !strings.Contains(body, "Logged in through AnyAuth") {
		t.Fatalf("App A did not show logged in user: %s", body)
	}
}

func TestProviderOnlyMode(t *testing.T) {
	cfg := Config{
		ProviderPort: freePort(t),
		DataDir:      t.TempDir(),
	}
	_, err := clientregistry.Add(cfg.DataDir, clientregistry.Client{
		ID:           "custom-app",
		Name:         "Custom App",
		Secret:       "custom-secret",
		RedirectURIs: []string{"http://127.0.0.1:18080/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}

	servers, cfg, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := servers.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
	}()
	if len(servers.servers) != 1 {
		t.Fatalf("server count = %d, want provider only", len(servers.servers))
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	provider := "http://127.0.0.1:" + itoa(cfg.ProviderPort)

	body := mustGetBody(t, client, provider+"/", http.StatusOK)
	if strings.Contains(body, "Demo App A") || strings.Contains(body, "demo-app-a") {
		t.Fatalf("provider-only home leaked demo app links or clients: %s", body)
	}
	body = mustGetBody(t, client, provider+"/.well-known/openid-configuration", http.StatusOK)
	if !strings.Contains(body, `"issuer":"`+provider+`"`) {
		t.Fatalf("discovery issuer missing from %s", body)
	}

	customAuthorize := provider + "/authorize?" + url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{"custom-app"},
		"redirect_uri":          []string{"http://127.0.0.1:18080/callback"},
		"scope":                 []string{"openid profile email"},
		"state":                 []string{"custom-state"},
		"nonce":                 []string{"custom-nonce"},
		"code_challenge":        []string{"custom-challenge"},
		"code_challenge_method": []string{"S256"},
	}.Encode()
	body = mustGetBody(t, client, customAuthorize, http.StatusOK)
	if !strings.Contains(body, "Sign in with AnyAuth") {
		t.Fatalf("expected registered client to reach login page, got %s", body)
	}

	demoAuthorize := provider + "/authorize?" + url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{"demo-app-a"},
		"redirect_uri":          []string{"http://127.0.0.1:7101/callback"},
		"scope":                 []string{"openid profile email"},
		"state":                 []string{"demo-state"},
		"nonce":                 []string{"demo-nonce"},
		"code_challenge":        []string{"demo-challenge"},
		"code_challenge_method": []string{"S256"},
	}.Encode()
	body = mustGetBody(t, client, demoAuthorize, http.StatusOK)
	if !strings.Contains(body, "unknown client_id") {
		t.Fatalf("expected built-in demo client to be absent, got %s", body)
	}
}

func TestProtectGatewayFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s authenticated=%s sub=%s name=%s email=%s",
			r.URL.String(),
			r.Header.Get("X-AnyAuth-Authenticated"),
			r.Header.Get("X-AnyAuth-Sub"),
			r.Header.Get("X-AnyAuth-Name"),
			r.Header.Get("X-AnyAuth-Email"),
		)
	}))
	defer upstream.Close()

	cfg := Config{
		ProviderPort:    freePort(t),
		ProtectPort:     freePort(t),
		ProtectUpstream: upstream.URL,
		DataDir:         t.TempDir(),
	}
	servers, cfg, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := servers.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
	}()
	if len(servers.servers) != 2 {
		t.Fatalf("server count = %d, want provider and protected proxy", len(servers.servers))
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	provider := "http://127.0.0.1:" + itoa(cfg.ProviderPort)
	gateway := "http://127.0.0.1:" + itoa(cfg.ProtectPort)

	loginURL := mustGetLocation(t, client, gateway+"/private?x=1")
	if !strings.HasPrefix(loginURL, "/__anyauth/login?return=") {
		t.Fatalf("login redirect = %s", loginURL)
	}
	authorizeURL := mustGetLocation(t, client, gateway+loginURL)
	if !strings.HasPrefix(authorizeURL, provider+"/authorize?") {
		t.Fatalf("authorize redirect = %s", authorizeURL)
	}
	body := mustGetBody(t, client, authorizeURL, http.StatusOK)
	if !strings.Contains(body, "Sign in with AnyAuth") {
		t.Fatalf("expected provider login page, got %s", body)
	}

	parsedAuthorize, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	callbackURL := mustPostLocation(t, client, provider+"/login", parsedAuthorize.Query())
	if !strings.HasPrefix(callbackURL, gateway+"/__anyauth/callback?") {
		t.Fatalf("callback redirect = %s", callbackURL)
	}
	returnURL := mustGetLocation(t, client, callbackURL)
	if returnURL != "/private?x=1" {
		t.Fatalf("return redirect = %s, want /private?x=1", returnURL)
	}

	req, err := http.NewRequest(http.MethodGet, gateway+"/private?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-AnyAuth-Email", "spoofed@example.com")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("protected request status = %d, want 200, body: %s", resp.StatusCode, string(raw))
	}
	body = string(raw)
	for _, want := range []string{
		"path=/private?x=1",
		"authenticated=true",
		"sub=local-user",
		"name=Local User",
		"email=local.user@anyauth.local",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("protected upstream body missing %q from %s", want, body)
		}
	}
	if strings.Contains(body, "spoofed@example.com") {
		t.Fatalf("protected proxy forwarded spoofed identity header: %s", body)
	}
}

func TestProtectGatewayWithDelegation(t *testing.T) {
	dataDir := t.TempDir()
	providerPort := freePort(t)
	protectPort := freePort(t)
	agent, err := agentregistry.Add(dataDir, agentregistry.Agent{
		ID:   "codex",
		Name: "Codex Local Agent",
		Kind: "cli",
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.LoadOrCreateRSAKey(filepath.Join(dataDir, "dev-private-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	record, token, err := delegation.Create(dataDir, delegation.CreateRequest{
		Issuer:   delegation.IssuerForProviderPort(providerPort),
		Audience: delegation.AudienceForProtectPort(protectPort),
		Human:    userstore.DefaultProfile(),
		Agent:    agent,
		Scopes:   []string{"app.read", "app.write"},
		Note:     "protect gateway test",
		TTL:      30 * time.Minute,
		Key:      key,
	})
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s authenticated=%s actor=%s sub=%s human=%s agent=%s delegation=%s scopes=%s authz=%s",
			r.URL.String(),
			r.Header.Get("X-AnyAuth-Authenticated"),
			r.Header.Get("X-AnyAuth-Actor-Type"),
			r.Header.Get("X-AnyAuth-Sub"),
			r.Header.Get("X-AnyAuth-Human-Sub"),
			r.Header.Get("X-AnyAuth-Agent-ID"),
			r.Header.Get("X-AnyAuth-Delegation-ID"),
			r.Header.Get("X-AnyAuth-Scopes"),
			r.Header.Get("Authorization"),
		)
	}))
	defer upstream.Close()

	cfg := Config{
		ProviderPort:      providerPort,
		ProtectPort:       protectPort,
		ProtectUpstream:   upstream.URL,
		DataDir:           dataDir,
		RequireDelegation: true,
	}
	servers, cfg, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := servers.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
	}()

	client := &http.Client{}
	gateway := "http://127.0.0.1:" + itoa(cfg.ProtectPort)

	body := mustGetBody(t, client, gateway+"/private?x=1", http.StatusUnauthorized)
	if !strings.Contains(body, "delegation bearer token is required") {
		t.Fatalf("expected missing token failure, got %s", body)
	}

	req, err := http.NewRequest(http.MethodGet, gateway+"/private?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-AnyAuth-Agent-ID", "spoofed-agent")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delegated request status = %d, want 200, body: %s", resp.StatusCode, string(raw))
	}
	body = string(raw)
	for _, want := range []string{
		"path=/private?x=1",
		"authenticated=true",
		"actor=agent",
		"sub=local-user",
		"human=local-user",
		"agent=codex",
		"delegation=" + record.ID,
		"scopes=app.read app.write",
		"authz=",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("delegated upstream body missing %q from %s", want, body)
		}
	}
	if strings.Contains(body, "spoofed-agent") || strings.Contains(body, token) {
		t.Fatalf("protected proxy leaked spoofed header or token: %s", body)
	}

	req, err = http.NewRequest(http.MethodGet, gateway+"/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token[:len(token)-1]+"x")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("tampered token status = %d, want 401, body: %s", resp.StatusCode, string(raw))
	}

	events, err := auditlog.Load(dataDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("audit event count = %d, want 3: %+v", len(events), events)
	}
	if events[0].Type != "proxy.deny" || events[0].Decision != "deny" || !strings.Contains(events[0].Reason, "required") {
		t.Fatalf("unexpected first audit event: %+v", events[0])
	}
	if events[1].Type != "proxy.allow" || events[1].Decision != "allow" || events[1].AgentID != "codex" || events[1].DelegationID != record.ID {
		t.Fatalf("unexpected second audit event: %+v", events[1])
	}
	if events[2].Type != "proxy.deny" || events[2].Decision != "deny" {
		t.Fatalf("unexpected third audit event: %+v", events[2])
	}
}

func TestProtectGatewayEnforcesPolicy(t *testing.T) {
	dataDir := t.TempDir()
	providerPort := freePort(t)
	protectPort := freePort(t)
	agent, err := agentregistry.Add(dataDir, agentregistry.Agent{
		ID:   "codex",
		Name: "Codex Local Agent",
		Kind: "cli",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Add(dataDir, policy.Rule{
		ID:             "allow-allowed",
		Effect:         policy.EffectAllow,
		Methods:        []string{http.MethodGet},
		PathPrefix:     "/allowed",
		RequiredScopes: []string{"app.read"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Add(dataDir, policy.Rule{
		ID:         "deny-admin",
		Effect:     policy.EffectDeny,
		PathPrefix: "/admin",
	}); err != nil {
		t.Fatal(err)
	}
	key, err := jose.LoadOrCreateRSAKey(filepath.Join(dataDir, "dev-private-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	_, readToken, err := delegation.Create(dataDir, delegation.CreateRequest{
		Issuer:   delegation.IssuerForProviderPort(providerPort),
		Audience: delegation.AudienceForProtectPort(protectPort),
		Human:    userstore.DefaultProfile(),
		Agent:    agent,
		Scopes:   []string{"app.read"},
		TTL:      30 * time.Minute,
		Key:      key,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, writeToken, err := delegation.Create(dataDir, delegation.CreateRequest{
		Issuer:   delegation.IssuerForProviderPort(providerPort),
		Audience: delegation.AudienceForProtectPort(protectPort),
		Human:    userstore.DefaultProfile(),
		Agent:    agent,
		Scopes:   []string{"app.write"},
		TTL:      30 * time.Minute,
		Key:      key,
	})
	if err != nil {
		t.Fatal(err)
	}

	var upstreamHits int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&upstreamHits, 1)
		fmt.Fprintf(w, "path=%s agent=%s scopes=%s",
			r.URL.String(),
			r.Header.Get("X-AnyAuth-Agent-ID"),
			r.Header.Get("X-AnyAuth-Scopes"),
		)
	}))
	defer upstream.Close()

	cfg := Config{
		ProviderPort:      providerPort,
		ProtectPort:       protectPort,
		ProtectUpstream:   upstream.URL,
		DataDir:           dataDir,
		RequireDelegation: true,
	}
	servers, cfg, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := servers.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
	}()

	client := &http.Client{}
	gateway := "http://127.0.0.1:" + itoa(cfg.ProtectPort)

	body := mustGetBearerBody(t, client, gateway+"/allowed/doc", readToken, http.StatusOK)
	if !strings.Contains(body, "path=/allowed/doc") || !strings.Contains(body, "scopes=app.read") {
		t.Fatalf("allowed response missing expected data: %s", body)
	}
	body = mustGetBearerBody(t, client, gateway+"/allowed/doc", writeToken, http.StatusForbidden)
	if !strings.Contains(body, "missing required scope") {
		t.Fatalf("expected missing scope denial, got %s", body)
	}
	body = mustGetBearerBody(t, client, gateway+"/admin", readToken, http.StatusForbidden)
	if !strings.Contains(body, "matched deny policy deny-admin") {
		t.Fatalf("expected deny policy denial, got %s", body)
	}
	body = mustGetBearerBody(t, client, gateway+"/unmatched", readToken, http.StatusForbidden)
	if !strings.Contains(body, "no matching allow policy") {
		t.Fatalf("expected default policy denial, got %s", body)
	}
	if got := atomic.LoadInt64(&upstreamHits); got != 1 {
		t.Fatalf("upstream hits = %d, want only the allowed request to reach upstream", got)
	}

	events, err := auditlog.Load(dataDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("audit event count = %d, want 4: %+v", len(events), events)
	}
	if events[0].Type != "proxy.allow" || !strings.Contains(events[0].Reason, "allow-allowed") {
		t.Fatalf("unexpected allow audit event: %+v", events[0])
	}
	for _, event := range events[1:] {
		if event.Type != "proxy.deny" || event.Decision != "deny" || event.AgentID != "codex" {
			t.Fatalf("unexpected deny audit event: %+v", event)
		}
	}
}

func TestProtectRejectsInvalidUpstream(t *testing.T) {
	cfg := Config{
		ProviderPort:    freePort(t),
		ProtectPort:     freePort(t),
		ProtectUpstream: "127.0.0.1:3000",
		DataDir:         t.TempDir(),
	}
	servers, _, err := Start(cfg)
	if err == nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = servers.Shutdown(ctx)
		}()
		t.Fatal("expected invalid protect upstream to fail")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func mustGetLocation(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 302, body: %s", target, resp.StatusCode, string(raw))
	}
	return resp.Header.Get("Location")
}

func mustPostLocation(t *testing.T, client *http.Client, target string, values url.Values) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s status = %d, want 302, body: %s", target, resp.StatusCode, string(raw))
	}
	return resp.Header.Get("Location")
}

func mustPostBody(t *testing.T, client *http.Client, target string, values url.Values, status int) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("POST %s status = %d, want %d, body: %s", target, resp.StatusCode, status, string(raw))
	}
	return string(raw)
}

func mustGetBody(t *testing.T, client *http.Client, target string, status int) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("GET %s status = %d, want %d, body: %s", target, resp.StatusCode, status, string(raw))
	}
	return string(raw)
}

func mustGetBearerBody(t *testing.T, client *http.Client, target string, token string, status int) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("GET %s status = %d, want %d, body: %s", target, resp.StatusCode, status, string(raw))
	}
	return string(raw)
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
