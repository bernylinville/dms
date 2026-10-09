package secretkey

import (
	"bytes"
	"strings"
	"testing"
)

// Fail-safe for CVE-2025-15107 / GHSA-43h9-hc38-qph5: an empty or short root
// secret must never allow a binary to boot on known default keys. These tests
// pin the Validate contract used by the dms and sqled startup assemblies.
func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{"empty secret_key", "", true},
		{"8 bytes", "12345678", true},
		{"31 bytes", strings.Repeat("a", 31), true},
		{"exactly 32 bytes", strings.Repeat("a", 32), false},
		{"64 hex chars", "8aac552286da2f3495aead89fb05136a84dfa9827a9a801fa0ea19ff3b361026", false},
	} {
		err := Validate(tc.secret)
		if gotErr := err != nil; gotErr != tc.wantErr {
			t.Errorf("%s: Validate() error = %v, want error = %v", tc.name, err, tc.wantErr)
		}
	}
}

// JWT and AES keys must be derived under distinct info domains so that the
// two usages never share key material, and derivation must be deterministic.
func TestDeriveKeyDomainSeparation(t *testing.T) {
	root := "8aac552286da2f3495aead89fb05136a84dfa9827a9a801fa0ea19ff3b361026"

	jwtKey, err := DeriveKey(root, InfoJWT)
	if err != nil {
		t.Fatalf("derive jwt key: %v", err)
	}
	aesKey, err := DeriveKey(root, InfoAES)
	if err != nil {
		t.Fatalf("derive aes key: %v", err)
	}
	if len(jwtKey) != DerivedKeyLength || len(aesKey) != DerivedKeyLength {
		t.Fatalf("derived key length = %d/%d, want %d", len(jwtKey), len(aesKey), DerivedKeyLength)
	}
	if bytes.Equal(jwtKey, aesKey) {
		t.Fatal("jwt and aes domains must not derive the same key")
	}

	jwtKey2, err := DeriveKey(root, InfoJWT)
	if err != nil {
		t.Fatalf("derive jwt key again: %v", err)
	}
	if !bytes.Equal(jwtKey, jwtKey2) {
		t.Fatal("derivation must be deterministic")
	}

	// the derived key must not be the raw root secret
	if bytes.Equal(jwtKey, []byte(root)) {
		t.Fatal("derived jwt key must differ from the raw root secret")
	}
}
