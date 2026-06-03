package localdev

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLocalSSOFlow(t *testing.T) {
	cfg := Config{
		ProviderPort: freePort(t),
		AppAPort:     freePort(t),
		AppBPort:     freePort(t),
		DataDir:      t.TempDir(),
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

func itoa(value int) string {
	return strconv.Itoa(value)
}
