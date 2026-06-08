package userstore

import "testing"

func TestLoadMissingReturnsDefaultProfile(t *testing.T) {
	profile, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if profile.Sub != "local-user" {
		t.Fatalf("Sub = %q, want local-user", profile.Sub)
	}
	if HasPIN(profile) {
		t.Fatal("default profile should not have PIN configured")
	}
}

func TestSetAndVerifyPIN(t *testing.T) {
	dataDir := t.TempDir()
	profile, err := SetPIN(dataDir, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if !HasPIN(profile) {
		t.Fatal("profile should have PIN configured")
	}

	loaded, err := Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPIN(loaded, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected PIN verification to pass")
	}
	ok, err = VerifyPIN(loaded, "000000")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected wrong PIN verification to fail")
	}
}

func TestClearPIN(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := SetPIN(dataDir, "123456"); err != nil {
		t.Fatal(err)
	}

	profile, err := ClearPIN(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if HasPIN(profile) {
		t.Fatal("profile should not have PIN configured")
	}

	loaded, err := Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if HasPIN(loaded) {
		t.Fatal("loaded profile should not have PIN configured")
	}
	ok, err := VerifyPIN(loaded, "")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("verification should pass when no PIN is configured")
	}
}

func TestSetPINRejectsShortPIN(t *testing.T) {
	_, err := SetPIN(t.TempDir(), "12345")
	if err == nil {
		t.Fatal("expected short PIN error")
	}
}
