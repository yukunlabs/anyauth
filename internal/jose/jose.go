package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

func Base64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func PKCES256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return Base64URL(sum[:])
}

func RandomURLToken(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return Base64URL(raw), nil
}

func LoadOrCreateRSAKey(path string) (*rsa.PrivateKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("invalid RSA private key PEM at %s", path)
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func RSAJWK(publicKey *rsa.PublicKey, kid string) map[string]string {
	exponent := big.NewInt(int64(publicKey.E)).Bytes()
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   Base64URL(publicKey.N.Bytes()),
		"e":   Base64URL(exponent),
	}
}

func SignJWT(payload map[string]any, key *rsa.PrivateKey, kid string) (string, error) {
	header := map[string]any{
		"typ": "JWT",
		"alg": "RS256",
		"kid": kid,
	}
	headerPart, err := jsonPart(header)
	if err != nil {
		return "", err
	}
	payloadPart, err := jsonPart(payload)
	if err != nil {
		return "", err
	}
	signingInput := headerPart + "." + payloadPart

	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + Base64URL(signature), nil
}

func VerifyRS256JWT(token string, publicKey *rsa.PublicKey) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token must contain three JWT parts")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, err
	}
	if header["alg"] != "RS256" {
		return nil, fmt.Errorf("unexpected JWT alg: %v", header["alg"])
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	signingInput := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sum[:], signature); err != nil {
		return nil, err
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func jsonPart(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return Base64URL(raw), nil
}
