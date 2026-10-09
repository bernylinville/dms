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
	// TestVectorRootSecret is a fixed, public, production-shaped root secret
	// (openssl rand -hex 32 output shape). It is not a real secret.
	TestVectorRootSecret = "8aac552286da2f3495aead89fb05136a84dfa9827a9a801fa0ea19ff3b361026"

	// TestVectorJWTKeyHex = HKDF-SHA256(root, salt=nil, info=InfoJWT, L=32)
	TestVectorJWTKeyHex = "46c01319af726406080a5db116914a81ef436dcab291ac34005f7615f02ddd5f"

	// TestVectorAESKeyHex = HKDF-SHA256(root, salt=nil, info=InfoAES, L=32)
	TestVectorAESKeyHex = "4bd1dc96e284cf39a3106bcddb6e6011d31a5a6f9cdffceef4d9bfd52166a7db"
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
