package secretkey

import (
	"encoding/hex"
	"testing"
)

// Cross-repo HKDF consistency test vectors (sqle-jwt-secret-fix task 03).
//
// The sqle fork vendors a copy of this package at
// vendor/github.com/actiontech/dms/pkg/dms-common/pkg/secretkey and mirrors
// this file byte-for-byte. Both copies must derive identical keys from the
// same root secret: tokens signed by one binary are verified by the other,
// and AES ciphertexts written by the migration tool (task 04) must decrypt
// under DeriveKey(root, InfoAES) in both repos.
//
// If these tests fail after syncing upstream code, an HKDF parameter (hash,
// salt, info domain, key length) has drifted and the CVE-2025-15107
// hardening is broken. Do NOT update the expected values to make the tests
// pass without a migration plan for all existing tokens and ciphertexts.
const (
	// TestVectorRootSecret is the fixed, public, canonical cross-repo test
	// root secret agreed in task 03. It is not a real secret.
	TestVectorRootSecret = "sqle-jwt-secret-fix-crossrepo-vector-0001"

	// TestVectorJWTKeyHex = HKDF-SHA256(root, salt=nil, info=InfoJWT, L=32)
	TestVectorJWTKeyHex = "7a9fb850c7f34b36751da8b5273142c34d8c18b95053dcd3ad34fa7dbad20bfc"

	// TestVectorAESKeyHex = HKDF-SHA256(root, salt=nil, info=InfoAES, L=32)
	TestVectorAESKeyHex = "fb06443d1eb9ba92ce6d8becc77ccaf3dfe7670d54564292f9e263a61902e6fe"
)

func TestDeriveKeyTestVectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		info string
		want string
	}{
		{"jwt domain", InfoJWT, TestVectorJWTKeyHex},
		{"aes domain", InfoAES, TestVectorAESKeyHex},
	} {
		got, err := DeriveKey(TestVectorRootSecret, tc.info)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("%s: derived key drift:\n got  %s\n want %s\nHKDF parameters changed; see file comment before touching expected values", tc.name, hex.EncodeToString(got), tc.want)
		}
	}
}
