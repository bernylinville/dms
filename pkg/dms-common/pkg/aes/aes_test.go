package aes

import (
	"testing"
)

// Regression tests for CVE-2025-15107 / GHSA-43h9-hc38-qph5 (AES side): the
// data-encryption key must be derived from the root secret via HKDF (domain
// actiontech-dms/aes/v1) instead of using the configured secret verbatim,
// and an empty secret_key must be refused instead of silently keeping the
// publicly known default key 471F77D078C5994BD06B65B8B5B1935B.

// rootSecretNotAesSized is longer than 32 bytes and not a valid raw AES key
// size (16/24/32); after HKDF derivation such root secrets must be accepted.
const rootSecretNotAesSized = "8aac552286da2f3495aead89fb05136a84dfa9827a9a801fa0ea19ff3b361026"

func restoreStdKey(t *testing.T) {
	t.Helper()
	origKey := std.SecretKey
	t.Cleanup(func() {
		std.SecretKey = origKey
	})
}

// The production incident configuration: secret_key left empty. The reset
// must fail instead of silently keeping the default key.
func TestResetAesSecretKeyEmptyRefused(t *testing.T) {
	if err := ResetAesSecretKey(""); err == nil {
		t.Fatal("empty secret_key was accepted; the AES key must not silently fall back to the publicly known default key (CVE-2025-15107)")
	}
}

// Root secrets are no longer constrained to raw AES key sizes: a 64-char
// root secret must yield a working 32-byte derived key (encrypt/decrypt
// roundtrip succeeds under it).
func TestResetAesSecretKeyDerivesWorkingKey(t *testing.T) {
	restoreStdKey(t)

	if err := ResetAesSecretKey(rootSecretNotAesSized); err != nil {
		t.Fatalf("root secret of %d bytes (not a raw AES key size) must be accepted after HKDF derivation: %v", len(rootSecretNotAesSized), err)
	}

	const plain = "CVE-2025-15107 roundtrip probe"
	encrypted, err := AesEncrypt(plain)
	if err != nil {
		t.Fatalf("encrypt under derived key: %v", err)
	}
	decrypted, err := AesDecrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt under derived key: %v", err)
	}
	if decrypted != plain {
		t.Fatalf("roundtrip mismatch: got %q want %q", decrypted, plain)
	}
}
