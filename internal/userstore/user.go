package userstore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
)

const (
	FileName          = "user.json"
	DefaultIterations = 210000
	DefaultKeyLength  = 32
)

type Profile struct {
	Version     int          `json:"version"`
	Sub         string       `json:"sub"`
	Name        string       `json:"name"`
	Email       string       `json:"email"`
	PINVerifier *PINVerifier `json:"pin_verifier,omitempty"`
}

type PINVerifier struct {
	Algorithm  string `json:"algorithm"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
}

func DefaultProfile() Profile {
	return Profile{
		Version: 1,
		Sub:     "local-user",
		Name:    "Local User",
		Email:   "local.user@anyauth.local",
	}
}

func Path(dataDir string) string {
	if dataDir == "" {
		dataDir = ".anyauth"
	}
	return filepath.Join(dataDir, FileName)
}

func Load(dataDir string) (Profile, error) {
	raw, err := os.ReadFile(Path(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return DefaultProfile(), nil
	}
	if err != nil {
		return Profile{}, err
	}

	var profile Profile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return Profile{}, err
	}
	if profile.Version == 0 {
		profile.Version = 1
	}
	if profile.Sub == "" {
		return Profile{}, fmt.Errorf("user sub is required")
	}
	if profile.Name == "" {
		profile.Name = profile.Sub
	}
	return profile, nil
}

func Save(dataDir string, profile Profile) error {
	if profile.Version == 0 {
		profile.Version = 1
	}
	if profile.Sub == "" {
		return fmt.Errorf("user sub is required")
	}
	if profile.Name == "" {
		profile.Name = profile.Sub
	}

	path := Path(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func SetPIN(dataDir string, pin string) (Profile, error) {
	if err := ValidatePIN(pin); err != nil {
		return Profile{}, err
	}
	profile, err := Load(dataDir)
	if err != nil {
		return Profile{}, err
	}
	verifier, err := NewPINVerifier(pin)
	if err != nil {
		return Profile{}, err
	}
	profile.PINVerifier = verifier
	if err := Save(dataDir, profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func ClearPIN(dataDir string) (Profile, error) {
	profile, err := Load(dataDir)
	if err != nil {
		return Profile{}, err
	}
	profile.PINVerifier = nil
	if err := Save(dataDir, profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func ValidatePIN(pin string) error {
	if len(pin) < 6 {
		return fmt.Errorf("PIN must be at least 6 characters")
	}
	if len(pin) > 128 {
		return fmt.Errorf("PIN must be at most 128 characters")
	}
	return nil
}

func NewPINVerifier(pin string) (*PINVerifier, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	digest := pbkdf2(sha256.New, []byte(pin), salt, DefaultIterations, DefaultKeyLength)
	return &PINVerifier{
		Algorithm:  "pbkdf2-sha256",
		Iterations: DefaultIterations,
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		Hash:       base64.RawURLEncoding.EncodeToString(digest),
	}, nil
}

func HasPIN(profile Profile) bool {
	return profile.PINVerifier != nil
}

func VerifyPIN(profile Profile, pin string) (bool, error) {
	if profile.PINVerifier == nil {
		return true, nil
	}
	verifier := profile.PINVerifier
	if verifier.Algorithm != "pbkdf2-sha256" {
		return false, fmt.Errorf("unsupported PIN verifier algorithm %q", verifier.Algorithm)
	}
	if verifier.Iterations <= 0 {
		return false, fmt.Errorf("invalid PIN verifier iterations")
	}
	salt, err := base64.RawURLEncoding.DecodeString(verifier.Salt)
	if err != nil {
		return false, err
	}
	want, err := base64.RawURLEncoding.DecodeString(verifier.Hash)
	if err != nil {
		return false, err
	}
	got := pbkdf2(sha256.New, []byte(pin), salt, verifier.Iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func pbkdf2(h func() hash.Hash, password []byte, salt []byte, iterations int, keyLength int) []byte {
	mac := hmac.New(h, password)
	hashLength := mac.Size()
	blocks := (keyLength + hashLength - 1) / hashLength
	output := make([]byte, 0, blocks*hashLength)
	var counter [4]byte

	for block := 1; block <= blocks; block++ {
		mac.Reset()
		mac.Write(salt)
		binary.BigEndian.PutUint32(counter[:], uint32(block))
		mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)

		for i := 1; i < iterations; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		output = append(output, t...)
	}
	return output[:keyLength]
}
