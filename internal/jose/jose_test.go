package jose

import (
	"strings"
	"testing"
)

func TestPKCES256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := PKCES256(verifier); got != want {
		t.Fatalf("PKCES256() = %q, want %q", got, want)
	}
}

func TestSignJWTAndDecodePayload(t *testing.T) {
	t.Setenv("ANYAUTH_TEST", "1")
	key, err := LoadOrCreateRSAKey(t.TempDir() + "/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	token, err := SignJWT(map[string]any{
		"iss": "http://127.0.0.1:7100",
		"sub": "local-user",
	}, key, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if parts := strings.Count(token, "."); parts != 2 {
		t.Fatalf("JWT contains %d dots, want 2", parts)
	}

	payload, err := VerifyRS256JWT(token, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if payload["sub"] != "local-user" {
		t.Fatalf("sub = %v, want local-user", payload["sub"])
	}
}
