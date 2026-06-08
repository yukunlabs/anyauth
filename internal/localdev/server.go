package localdev

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yukunlabs/anyauth/internal/clientregistry"
	"github.com/yukunlabs/anyauth/internal/delegation"
	"github.com/yukunlabs/anyauth/internal/jose"
	"github.com/yukunlabs/anyauth/internal/userstore"
)

const keyID = "anyauth-local-dev-key"

type Config struct {
	ProviderPort      int
	AppAPort          int
	AppBPort          int
	ProtectPort       int
	DataDir           string
	DemoApps          bool
	ProtectUpstream   string
	RequireDelegation bool
}

type app struct {
	cfg        Config
	issuer     string
	signingKey *rsa.PrivateKey
	store      *store
	clients    map[string]client
	user       user
	profile    userstore.Profile
}

type client struct {
	ID           string
	Name         string
	Secret       string
	RedirectURIs map[string]bool
}

type user struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type authCode struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	User                user
	ExpiresAt           time.Time
}

type providerSession struct {
	User      user
	CreatedAt time.Time
}

type accessToken struct {
	ClientID  string
	Scope     string
	User      user
	ExpiresAt time.Time
}

type demoState struct {
	ClientID string
	Nonce    string
	Verifier string
	Created  time.Time
}

type demoSession struct {
	Claims      map[string]any
	AccessToken string
	CreatedAt   time.Time
}

type protectState struct {
	Nonce      string
	Verifier   string
	ReturnPath string
	Created    time.Time
}

type protectSession struct {
	Claims    map[string]any
	CreatedAt time.Time
}

type protectIdentity struct {
	ActorType    string
	HumanSub     string
	HumanName    string
	HumanEmail   string
	AgentID      string
	AgentName    string
	DelegationID string
	TokenID      string
	Scopes       []string
}

type store struct {
	mu               sync.Mutex
	providerSessions map[string]providerSession
	authCodes        map[string]authCode
	accessTokens     map[string]accessToken
	demoStates       map[string]demoState
	demoSessions     map[string]demoSession
	protectStates    map[string]protectState
	protectSessions  map[string]protectSession
}

type ServerSet struct {
	servers []*http.Server
}

func newStore() *store {
	return &store{
		providerSessions: map[string]providerSession{},
		authCodes:        map[string]authCode{},
		accessTokens:     map[string]accessToken{},
		demoStates:       map[string]demoState{},
		demoSessions:     map[string]demoSession{},
		protectStates:    map[string]protectState{},
		protectSessions:  map[string]protectSession{},
	}
}

func Run(cfg Config) error {
	serverSet, cfg, err := Start(cfg)
	if err != nil {
		return err
	}

	if cfg.ProtectUpstream != "" {
		fmt.Println("AnyAuth protected proxy is running.")
	} else if cfg.DemoApps {
		fmt.Println("AnyAuth local demo is running.")
	} else {
		fmt.Println("AnyAuth local provider is running.")
	}
	fmt.Printf("  Provider:   http://127.0.0.1:%d\n", cfg.ProviderPort)
	if cfg.ProtectUpstream != "" {
		fmt.Printf("  Protected:  http://127.0.0.1:%d -> %s\n", cfg.ProtectPort, cfg.ProtectUpstream)
		if cfg.RequireDelegation {
			fmt.Println("  Mode:       agent delegation required")
		}
	}
	if cfg.DemoApps {
		fmt.Printf("  Demo App A: http://127.0.0.1:%d\n", cfg.AppAPort)
		fmt.Printf("  Demo App B: http://127.0.0.1:%d\n", cfg.AppBPort)
	}
	fmt.Println("Press Ctrl+C to stop.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return serverSet.Shutdown(ctx)
}

func Start(cfg Config) (*ServerSet, Config, error) {
	if cfg.ProviderPort == 0 {
		cfg.ProviderPort = 7100
	}
	if cfg.ProtectUpstream != "" && cfg.ProtectPort == 0 {
		cfg.ProtectPort = 7200
	}
	if cfg.DemoApps {
		if cfg.AppAPort == 0 {
			cfg.AppAPort = 7101
		}
		if cfg.AppBPort == 0 {
			cfg.AppBPort = 7102
		}
	}
	if cfg.DataDir == "" {
		cfg.DataDir = ".anyauth"
	}
	var protectUpstream *url.URL
	if cfg.ProtectUpstream != "" {
		parsed, err := url.Parse(cfg.ProtectUpstream)
		if err != nil {
			return nil, cfg, err
		}
		if parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, cfg, fmt.Errorf("protect upstream must be an absolute http or https URL")
		}
		protectUpstream = parsed
	}

	keyPath := filepath.Join(cfg.DataDir, "dev-private-key.pem")
	key, err := jose.LoadOrCreateRSAKey(keyPath)
	if err != nil {
		return nil, cfg, err
	}
	profile, err := userstore.Load(cfg.DataDir)
	if err != nil {
		return nil, cfg, err
	}

	a := &app{
		cfg:        cfg,
		issuer:     fmt.Sprintf("http://127.0.0.1:%d", cfg.ProviderPort),
		signingKey: key,
		store:      newStore(),
		user: user{
			Sub:   profile.Sub,
			Name:  profile.Name,
			Email: profile.Email,
		},
		profile: profile,
	}
	a.clients = map[string]client{}
	if cfg.DemoApps {
		a.clients["demo-app-a"] = client{
			ID:     "demo-app-a",
			Name:   "Demo App A",
			Secret: "demo-app-a-secret",
			RedirectURIs: map[string]bool{
				fmt.Sprintf("http://127.0.0.1:%d/callback", cfg.AppAPort): true,
			},
		}
		a.clients["demo-app-b"] = client{
			ID:     "demo-app-b",
			Name:   "Demo App B",
			Secret: "demo-app-b-secret",
			RedirectURIs: map[string]bool{
				fmt.Sprintf("http://127.0.0.1:%d/callback", cfg.AppBPort): true,
			},
		}
	}
	registeredClients, err := clientregistry.Load(cfg.DataDir)
	if err != nil {
		return nil, cfg, err
	}
	for _, registered := range registeredClients {
		redirectURIs := map[string]bool{}
		for _, redirectURI := range registered.RedirectURIs {
			redirectURIs[redirectURI] = true
		}
		a.clients[registered.ID] = client{
			ID:           registered.ID,
			Name:         registered.Name,
			Secret:       registered.Secret,
			RedirectURIs: redirectURIs,
		}
	}
	if protectUpstream != nil {
		a.clients[protectClientID(cfg.ProtectPort)] = client{
			ID:     protectClientID(cfg.ProtectPort),
			Name:   "AnyAuth Protected Proxy",
			Secret: protectClientSecret(cfg.ProtectPort),
			RedirectURIs: map[string]bool{
				protectRedirectURI(cfg.ProtectPort): true,
			},
		}
	}

	servers := []*http.Server{
		{Addr: fmt.Sprintf("127.0.0.1:%d", cfg.ProviderPort), Handler: a.providerMux()},
	}
	if protectUpstream != nil {
		servers = append(servers,
			&http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", cfg.ProtectPort), Handler: a.protectMux(protectUpstream)},
		)
	}
	if cfg.DemoApps {
		servers = append(servers,
			&http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", cfg.AppAPort), Handler: a.demoMux("Demo App A", "demo-app-a", "demo-app-a-secret", cfg.AppAPort, "demo_app_a_session")},
			&http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", cfg.AppBPort), Handler: a.demoMux("Demo App B", "demo-app-b", "demo-app-b-secret", cfg.AppBPort, "demo_app_b_session")},
		)
	}

	for _, srv := range servers {
		listener, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return nil, cfg, err
		}
		go func(s *http.Server, ln net.Listener) {
			log.Printf("listening on http://%s", s.Addr)
			if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("server error on %s: %v", s.Addr, err)
			}
		}(srv, listener)
	}

	return &ServerSet{servers: servers}, cfg, nil
}

func (s *ServerSet) Shutdown(ctx context.Context) error {
	for _, srv := range s.servers {
		_ = srv.Shutdown(ctx)
	}
	return nil
}

func (a *app) providerMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.providerHome)
	mux.HandleFunc("/.well-known/openid-configuration", a.discovery)
	mux.HandleFunc("/jwks.json", a.jwks)
	mux.HandleFunc("/authorize", a.authorize)
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc("/token", a.token)
	mux.HandleFunc("/userinfo", a.userinfo)
	return mux
}

func (a *app) demoMux(appName, clientID, clientSecret string, port int, sessionCookie string) http.Handler {
	demo := &demoApp{
		root:          a,
		appName:       appName,
		clientID:      clientID,
		clientSecret:  clientSecret,
		port:          port,
		sessionCookie: sessionCookie,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", demo.home)
	mux.HandleFunc("/login", demo.login)
	mux.HandleFunc("/callback", demo.callback)
	mux.HandleFunc("/logout", demo.logout)
	return mux
}

func (a *app) protectMux(upstream *url.URL) http.Handler {
	protect := newProtectedApp(a, upstream, a.cfg.ProtectPort)
	mux := http.NewServeMux()
	mux.HandleFunc("/__anyauth/login", protect.login)
	mux.HandleFunc("/__anyauth/callback", protect.callback)
	mux.HandleFunc("/__anyauth/logout", protect.logout)
	mux.HandleFunc("/", protect.proxy)
	return mux
}

func (a *app) providerHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeHTML(w, "AnyAuth Local Provider", fmt.Sprintf(`
<h1>AnyAuth Local Provider</h1>
<p class="muted">Local-first SSO hub prototype.</p>
<ul>
  <li><a href="/.well-known/openid-configuration">Discovery metadata</a></li>
  <li><a href="/jwks.json">JWKS</a></li>
  %s
</ul>
<h2>Registered clients</h2>
%s`, a.demoLinksHTML(), a.clientsHTML()))
}

func (a *app) demoLinksHTML() string {
	if !a.cfg.DemoApps {
		return ""
	}
	return fmt.Sprintf(`
  <li><a href="http://127.0.0.1:%d">Demo App A</a></li>
  <li><a href="http://127.0.0.1:%d">Demo App B</a></li>`, a.cfg.AppAPort, a.cfg.AppBPort)
}

func (a *app) clientsHTML() string {
	if len(a.clients) == 0 {
		return `<p class="muted">No clients registered.</p>`
	}

	ids := make([]string, 0, len(a.clients))
	for id := range a.clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var body strings.Builder
	body.WriteString("<ul>")
	for _, id := range ids {
		client := a.clients[id]
		body.WriteString("<li>")
		body.WriteString(html.EscapeString(client.ID))
		if client.Name != "" && client.Name != client.ID {
			body.WriteString(" - ")
			body.WriteString(html.EscapeString(client.Name))
		}
		body.WriteString("</li>")
	}
	body.WriteString("</ul>")
	return body.String()
}

func (a *app) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                a.issuer,
		"authorization_endpoint":                a.issuer + "/authorize",
		"token_endpoint":                        a.issuer + "/token",
		"userinfo_endpoint":                     a.issuer + "/userinfo",
		"jwks_uri":                              a.issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "name", "email"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (a *app) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{jose.RSAJWK(&a.signingKey.PublicKey, keyID)},
	})
}

func (a *app) authorize(w http.ResponseWriter, r *http.Request) {
	if err := a.validateAuthorize(r.URL.Query()); err != "" {
		writeHTML(w, "Authorize Error", "<h1>Authorize Error</h1><pre>"+html.EscapeString(err)+"</pre>")
		return
	}

	cookie, err := r.Cookie("anyauth_provider_session")
	if err == nil {
		a.store.mu.Lock()
		_, ok := a.store.providerSessions[cookie.Value]
		a.store.mu.Unlock()
		if ok {
			a.issueCodeRedirect(w, r.URL.Query(), nil)
			return
		}
	}

	var hidden strings.Builder
	for key, values := range r.URL.Query() {
		for _, value := range values {
			hidden.WriteString(fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, html.EscapeString(key), html.EscapeString(value)))
		}
	}

	pinControl := ""
	securityNote := `<p class="muted">No local PIN is configured. This development profile will continue without user verification.</p>`
	buttonText := "Continue as " + html.EscapeString(a.user.Email)
	if userstore.HasPIN(a.profile) {
		pinControl = `<p><label>PIN<br><input name="pin" type="password" autocomplete="current-password" autofocus required></label></p>`
		securityNote = `<p class="muted">Enter your local AnyAuth PIN to continue.</p>`
		buttonText = "Unlock AnyAuth"
	}

	writeHTML(w, "Sign in with AnyAuth", fmt.Sprintf(`
<h1>Sign in with AnyAuth</h1>
%s
<form method="post" action="/login">
  %s
  %s
  <button type="submit">%s</button>
</form>`, securityNote, hidden.String(), pinControl, buttonText))
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.validateAuthorize(r.Form); err != "" {
		writeHTML(w, "Login Error", "<h1>Login Error</h1><pre>"+html.EscapeString(err)+"</pre>")
		return
	}
	if userstore.HasPIN(a.profile) {
		ok, err := userstore.VerifyPIN(a.profile, r.Form.Get("pin"))
		if err != nil {
			writeHTMLStatus(w, http.StatusUnauthorized, "Login Error", "<h1>PIN verification failed</h1><pre>"+html.EscapeString(err.Error())+"</pre>")
			return
		}
		if !ok {
			writeHTMLStatus(w, http.StatusUnauthorized, "Login Error", "<h1>PIN verification failed</h1>")
			return
		}
	}

	sessionID, err := jose.RandomURLToken(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.store.mu.Lock()
	a.store.providerSessions[sessionID] = providerSession{User: a.user, CreatedAt: time.Now()}
	a.store.mu.Unlock()

	a.issueCodeRedirect(w, r.Form, &http.Cookie{
		Name:     "anyauth_provider_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *app) validateAuthorize(values url.Values) string {
	c, ok := a.clients[values.Get("client_id")]
	if !ok {
		return "unknown client_id"
	}
	if values.Get("response_type") != "code" {
		return "response_type must be code"
	}
	if !hasScope(values.Get("scope"), "openid") {
		return "scope must include openid"
	}
	if !c.RedirectURIs[values.Get("redirect_uri")] {
		return "redirect_uri does not match registered client"
	}
	if values.Get("code_challenge_method") != "S256" {
		return "only PKCE S256 is supported"
	}
	if values.Get("code_challenge") == "" {
		return "code_challenge is required"
	}
	return ""
}

func (a *app) issueCodeRedirect(w http.ResponseWriter, values url.Values, cookie *http.Cookie) {
	code, err := jose.RandomURLToken(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.store.mu.Lock()
	a.store.authCodes[code] = authCode{
		ClientID:            values.Get("client_id"),
		RedirectURI:         values.Get("redirect_uri"),
		Scope:               values.Get("scope"),
		Nonce:               values.Get("nonce"),
		CodeChallenge:       values.Get("code_challenge"),
		CodeChallengeMethod: values.Get("code_challenge_method"),
		User:                a.user,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}
	a.store.mu.Unlock()

	redirectValues := url.Values{"code": []string{code}}
	if state := values.Get("state"); state != "" {
		redirectValues.Set("state", state)
	}
	if cookie != nil {
		http.SetCookie(w, cookie)
	}
	w.Header().Set("Location", values.Get("redirect_uri")+"?"+redirectValues.Encode())
	w.WriteHeader(http.StatusFound)
}

func (a *app) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
		return
	}

	a.store.mu.Lock()
	codeData, ok := a.store.authCodes[r.Form.Get("code")]
	if ok {
		delete(a.store.authCodes, r.Form.Get("code"))
	}
	a.store.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "code is invalid or already used"})
		return
	}
	if time.Now().After(codeData.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "code expired"})
		return
	}
	c, ok := a.clients[codeData.ClientID]
	if !ok || r.Form.Get("client_id") != c.ID || r.Form.Get("client_secret") != c.Secret {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_client"})
		return
	}
	if r.Form.Get("redirect_uri") != codeData.RedirectURI {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
		return
	}
	if jose.PKCES256(r.Form.Get("code_verifier")) != codeData.CodeChallenge {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}

	issuedAt := time.Now()
	expiresIn := 3600
	payload := map[string]any{
		"iss":   a.issuer,
		"sub":   codeData.User.Sub,
		"aud":   codeData.ClientID,
		"iat":   issuedAt.Unix(),
		"exp":   issuedAt.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"name":  codeData.User.Name,
		"email": codeData.User.Email,
	}
	if codeData.Nonce != "" {
		payload["nonce"] = codeData.Nonce
	}

	idToken, err := jose.SignJWT(payload, a.signingKey, keyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	accessTokenValue, err := jose.RandomURLToken(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.store.mu.Lock()
	a.store.accessTokens[accessTokenValue] = accessToken{
		ClientID:  codeData.ClientID,
		Scope:     codeData.Scope,
		User:      codeData.User,
		ExpiresAt: issuedAt.Add(time.Duration(expiresIn) * time.Second),
	}
	a.store.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessTokenValue,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
		"id_token":     idToken,
	})
}

func (a *app) userinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	a.store.mu.Lock()
	tokenData, ok := a.store.accessTokens[token]
	a.store.mu.Unlock()
	if !ok || time.Now().After(tokenData.ExpiresAt) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, tokenData.User)
}

type protectSessionContextKey struct{}

type protectedApp struct {
	root          *app
	upstream      *url.URL
	port          int
	clientID      string
	clientSecret  string
	sessionCookie string
	reverseProxy  *httputil.ReverseProxy
}

func newProtectedApp(root *app, upstream *url.URL, port int) *protectedApp {
	app := &protectedApp{
		root:          root,
		upstream:      upstream,
		port:          port,
		clientID:      protectClientID(port),
		clientSecret:  protectClientSecret(port),
		sessionCookie: "anyauth_protect_session",
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = upstream.Host
		stripAnyAuthHeaders(req.Header)
		identity, ok := req.Context().Value(protectSessionContextKey{}).(protectIdentity)
		if !ok {
			return
		}
		if identity.ActorType == "agent" {
			req.Header.Del("Authorization")
		}
		req.Header.Set("X-AnyAuth-Authenticated", "true")
		setHeaderIfPresent(req.Header, "X-AnyAuth-Actor-Type", identity.ActorType)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Sub", identity.HumanSub)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Name", identity.HumanName)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Email", identity.HumanEmail)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Human-Sub", identity.HumanSub)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Human-Name", identity.HumanName)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Human-Email", identity.HumanEmail)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Agent-ID", identity.AgentID)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Agent-Name", identity.AgentName)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Delegation-ID", identity.DelegationID)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Token-ID", identity.TokenID)
		setHeaderIfPresent(req.Header, "X-AnyAuth-Scopes", strings.Join(identity.Scopes, " "))
	}
	app.reverseProxy = proxy
	return app
}

func (p *protectedApp) redirectURI() string {
	return protectRedirectURI(p.port)
}

func (p *protectedApp) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := jose.RandomURLToken(24)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nonce, err := jose.RandomURLToken(24)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := jose.RandomURLToken(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.root.store.mu.Lock()
	p.root.store.protectStates[state] = protectState{
		Nonce:      nonce,
		Verifier:   verifier,
		ReturnPath: cleanReturnPath(r.URL.Query().Get("return")),
		Created:    time.Now(),
	}
	p.root.store.mu.Unlock()

	values := url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{p.clientID},
		"redirect_uri":          []string{p.redirectURI()},
		"scope":                 []string{"openid profile email"},
		"state":                 []string{state},
		"nonce":                 []string{nonce},
		"code_challenge":        []string{jose.PKCES256(verifier)},
		"code_challenge_method": []string{"S256"},
	}
	http.Redirect(w, r, p.root.issuer+"/authorize?"+values.Encode(), http.StatusFound)
}

func (p *protectedApp) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	p.root.store.mu.Lock()
	stateData, ok := p.root.store.protectStates[state]
	if ok {
		delete(p.root.store.protectStates, state)
	}
	p.root.store.mu.Unlock()
	if !ok {
		writeHTML(w, "Login Error", "<h1>Invalid state</h1>")
		return
	}

	tokenResponse, err := p.exchangeCode(r.URL.Query().Get("code"), stateData.Verifier)
	if err != nil {
		writeHTML(w, "Token Error", "<h1>Token Error</h1><pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	if tokenResponse.Error != "" {
		body, _ := json.MarshalIndent(tokenResponse, "", "  ")
		writeHTML(w, "Token Error", "<h1>Token Error</h1><pre>"+html.EscapeString(string(body))+"</pre>")
		return
	}

	claims, err := jose.VerifyRS256JWT(tokenResponse.IDToken, &p.root.signingKey.PublicKey)
	if err != nil {
		writeHTML(w, "Login Error", "<h1>Invalid ID token</h1><pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	if err := validateIDTokenClaims(claims, p.root.issuer, p.clientID, stateData.Nonce); err != nil {
		writeHTML(w, "Login Error", "<h1>Invalid ID token claims</h1><pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	sessionID, err := jose.RandomURLToken(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.root.store.mu.Lock()
	p.root.store.protectSessions[sessionID] = protectSession{
		Claims:    claims,
		CreatedAt: time.Now(),
	}
	p.root.store.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     p.sessionCookie,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, stateData.ReturnPath, http.StatusFound)
}

func (p *protectedApp) proxy(w http.ResponseWriter, r *http.Request) {
	token, hasBearer, err := bearerToken(r)
	if err != nil {
		writeDelegationUnauthorized(w, err)
		return
	}
	if hasBearer {
		identity, err := p.delegatedIdentity(token)
		if err != nil {
			writeDelegationUnauthorized(w, err)
			return
		}
		ctx := context.WithValue(r.Context(), protectSessionContextKey{}, identity)
		p.reverseProxy.ServeHTTP(w, r.WithContext(ctx))
		return
	}
	if p.root.cfg.RequireDelegation {
		writeDelegationUnauthorized(w, fmt.Errorf("delegation bearer token is required"))
		return
	}

	session, ok := p.currentSession(r)
	if !ok {
		returnPath := cleanReturnPath(r.URL.RequestURI())
		http.Redirect(w, r, "/__anyauth/login?return="+url.QueryEscape(returnPath), http.StatusFound)
		return
	}
	ctx := context.WithValue(r.Context(), protectSessionContextKey{}, identityFromSession(session))
	p.reverseProxy.ServeHTTP(w, r.WithContext(ctx))
}

func (p *protectedApp) delegatedIdentity(token string) (protectIdentity, error) {
	ctx, err := delegation.ValidateToken(token, delegation.ValidateOptions{
		Issuer:    p.root.issuer,
		Audience:  delegation.AudienceForProtectPort(p.port),
		DataDir:   p.root.cfg.DataDir,
		PublicKey: &p.root.signingKey.PublicKey,
	})
	if err != nil {
		return protectIdentity{}, err
	}
	record := ctx.Delegation
	return protectIdentity{
		ActorType:    "agent",
		HumanSub:     record.HumanSub,
		HumanName:    record.HumanName,
		HumanEmail:   record.HumanEmail,
		AgentID:      record.AgentID,
		AgentName:    record.AgentName,
		DelegationID: record.ID,
		TokenID:      record.TokenID,
		Scopes:       ctx.Scopes,
	}, nil
}

func identityFromSession(session protectSession) protectIdentity {
	return protectIdentity{
		ActorType:  "human",
		HumanSub:   claimString(session.Claims, "sub"),
		HumanName:  claimString(session.Claims, "name"),
		HumanEmail: claimString(session.Claims, "email"),
	}
}

func bearerToken(r *http.Request) (string, bool, error) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return "", false, nil
	}
	parts := strings.Fields(auth)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false, fmt.Errorf("Authorization header must be Bearer <token>")
	}
	return parts[1], true, nil
}

func writeDelegationUnauthorized(w http.ResponseWriter, err error) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="anyauth", error="invalid_token"`)
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error":             "invalid_token",
		"error_description": err.Error(),
	})
}

func (p *protectedApp) exchangeCode(code, verifier string) (tokenResponse, error) {
	values := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{p.redirectURI()},
		"client_id":     []string{p.clientID},
		"client_secret": []string{p.clientSecret},
		"code_verifier": []string{verifier},
	}
	req, err := http.NewRequest(http.MethodPost, p.root.issuer+"/token", bytes.NewBufferString(values.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()

	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return tokenResponse{}, err
	}
	return token, nil
}

func (p *protectedApp) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(p.sessionCookie); err == nil {
		p.root.store.mu.Lock()
		delete(p.root.store.protectSessions, cookie.Value)
		p.root.store.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     p.sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (p *protectedApp) currentSession(r *http.Request) (protectSession, bool) {
	cookie, err := r.Cookie(p.sessionCookie)
	if err != nil {
		return protectSession{}, false
	}
	p.root.store.mu.Lock()
	defer p.root.store.mu.Unlock()
	session, ok := p.root.store.protectSessions[cookie.Value]
	return session, ok
}

func protectClientID(port int) string {
	return fmt.Sprintf("anyauth-protect-%d", port)
}

func protectClientSecret(port int) string {
	return fmt.Sprintf("anyauth-protect-%d-secret", port)
}

func protectRedirectURI(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/__anyauth/callback", port)
}

func cleanReturnPath(value string) string {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/"
	}
	return value
}

func stripAnyAuthHeaders(header http.Header) {
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-anyauth-") {
			header.Del(name)
		}
	}
}

func setHeaderIfPresent(header http.Header, name string, value string) {
	if value == "" {
		return
	}
	header.Set(name, value)
}

func claimString(claims map[string]any, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return text
}

type demoApp struct {
	root          *app
	appName       string
	clientID      string
	clientSecret  string
	port          int
	sessionCookie string
}

func (d *demoApp) redirectURI() string {
	return fmt.Sprintf("http://127.0.0.1:%d/callback", d.port)
}

func (d *demoApp) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	session, ok := d.currentSession(r)
	if ok {
		claims, _ := json.MarshalIndent(session.Claims, "", "  ")
		writeHTML(w, d.appName, fmt.Sprintf(`
<h1>%s</h1>
<p>Logged in through AnyAuth.</p>
<pre>%s</pre>
<p><a class="button" href="/logout">Log out of this app</a></p>
<p class="muted">Provider SSO session remains active, so logging in again should be instant.</p>`, html.EscapeString(d.appName), html.EscapeString(string(claims))))
		return
	}
	writeHTML(w, d.appName, fmt.Sprintf(`
<h1>%s</h1>
<p class="muted">This app trusts the local AnyAuth provider.</p>
<p><a class="button" href="/login">Login with AnyAuth</a></p>`, html.EscapeString(d.appName)))
}

func (d *demoApp) login(w http.ResponseWriter, r *http.Request) {
	state, err := jose.RandomURLToken(24)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nonce, err := jose.RandomURLToken(24)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := jose.RandomURLToken(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	d.root.store.mu.Lock()
	d.root.store.demoStates[state] = demoState{
		ClientID: d.clientID,
		Nonce:    nonce,
		Verifier: verifier,
		Created:  time.Now(),
	}
	d.root.store.mu.Unlock()

	values := url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{d.clientID},
		"redirect_uri":          []string{d.redirectURI()},
		"scope":                 []string{"openid profile email"},
		"state":                 []string{state},
		"nonce":                 []string{nonce},
		"code_challenge":        []string{jose.PKCES256(verifier)},
		"code_challenge_method": []string{"S256"},
	}
	http.Redirect(w, r, d.root.issuer+"/authorize?"+values.Encode(), http.StatusFound)
}

func (d *demoApp) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	d.root.store.mu.Lock()
	stateData, ok := d.root.store.demoStates[state]
	if ok {
		delete(d.root.store.demoStates, state)
	}
	d.root.store.mu.Unlock()
	if !ok || stateData.ClientID != d.clientID {
		writeHTML(w, "Login Error", "<h1>Invalid state</h1>")
		return
	}

	tokenResponse, err := d.exchangeCode(r.URL.Query().Get("code"), stateData.Verifier)
	if err != nil {
		writeHTML(w, "Token Error", "<h1>Token Error</h1><pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	if tokenResponse.Error != "" {
		body, _ := json.MarshalIndent(tokenResponse, "", "  ")
		writeHTML(w, "Token Error", "<h1>Token Error</h1><pre>"+html.EscapeString(string(body))+"</pre>")
		return
	}

	claims, err := jose.VerifyRS256JWT(tokenResponse.IDToken, &d.root.signingKey.PublicKey)
	if err != nil {
		writeHTML(w, "Login Error", "<h1>Invalid ID token</h1><pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	if err := d.validateClaims(claims, stateData.Nonce); err != nil {
		writeHTML(w, "Login Error", "<h1>Invalid ID token claims</h1><pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	sessionID, err := jose.RandomURLToken(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.root.store.mu.Lock()
	d.root.store.demoSessions[sessionID] = demoSession{
		Claims:      claims,
		AccessToken: tokenResponse.AccessToken,
		CreatedAt:   time.Now(),
	}
	d.root.store.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     d.sessionCookie,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (d *demoApp) validateClaims(claims map[string]any, nonce string) error {
	return validateIDTokenClaims(claims, d.root.issuer, d.clientID, nonce)
}

func validateIDTokenClaims(claims map[string]any, issuer string, clientID string, nonce string) error {
	if claims["iss"] != issuer {
		return fmt.Errorf("issuer mismatch")
	}
	if claims["aud"] != clientID {
		return fmt.Errorf("audience mismatch")
	}
	if claims["nonce"] != nonce {
		return fmt.Errorf("nonce mismatch")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("exp claim missing or invalid")
	}
	if time.Now().Unix() >= int64(exp) {
		return fmt.Errorf("ID token expired")
	}
	return nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (d *demoApp) exchangeCode(code, verifier string) (tokenResponse, error) {
	values := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{d.redirectURI()},
		"client_id":     []string{d.clientID},
		"client_secret": []string{d.clientSecret},
		"code_verifier": []string{verifier},
	}
	req, err := http.NewRequest(http.MethodPost, d.root.issuer+"/token", bytes.NewBufferString(values.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()

	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return tokenResponse{}, err
	}
	return token, nil
}

func (d *demoApp) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(d.sessionCookie); err == nil {
		d.root.store.mu.Lock()
		delete(d.root.store.demoSessions, cookie.Value)
		d.root.store.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     d.sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (d *demoApp) currentSession(r *http.Request) (demoSession, bool) {
	cookie, err := r.Cookie(d.sessionCookie)
	if err != nil {
		return demoSession{}, false
	}
	d.root.store.mu.Lock()
	defer d.root.store.mu.Unlock()
	session, ok := d.root.store.demoSessions[cookie.Value]
	return session, ok
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeHTML(w http.ResponseWriter, title string, body string) {
	writeHTMLStatus(w, http.StatusOK, title, body)
}

func writeHTMLStatus(w http.ResponseWriter, status int, title string, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%s</title>
  <style>
    :root { color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; padding: 40px; background: #f7f7f4; color: #1f2933; }
    main { max-width: 760px; margin: 0 auto; }
    .panel { background: #fff; border: 1px solid #d8d6cf; border-radius: 8px; padding: 24px; }
    a, button { font: inherit; }
    a.button, button { display: inline-block; border: 1px solid #1f2933; background: #1f2933; color: #fff; border-radius: 6px; padding: 9px 14px; text-decoration: none; cursor: pointer; }
    code, pre { background: #f0efea; border-radius: 6px; }
    pre { padding: 14px; overflow: auto; }
    .muted { color: #697386; }
  </style>
</head>
<body>
  <main class="panel">
    %s
  </main>
</body>
</html>`, html.EscapeString(title), body)
}

func hasScope(scopes string, want string) bool {
	for _, scope := range strings.Fields(scopes) {
		if scope == want {
			return true
		}
	}
	return false
}
