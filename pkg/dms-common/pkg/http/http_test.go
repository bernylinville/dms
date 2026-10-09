package http

import (
	"testing"
	"time"

	dmsCommonV1 "github.com/actiontech/dms/pkg/dms-common/api/dms/v1"
	"github.com/actiontech/dms/pkg/dms-common/api/jwt"

	jwtLib "github.com/golang-jwt/jwt/v4"
)

// Regression tests for CVE-2025-15107 / GHSA-43h9-hc38-qph5: the JWT signing
// key must never be the publicly known default "secret", neither by silently
// ignoring an empty secret_key nor by using a configured secret verbatim.
// The signing key is derived from the root secret via HKDF (domain
// actiontech-dms/jwt/v1), so tokens forged with the default key must fail
// signature validation in ParseUidFromJwtTokenStr — the parse entry shared by
// the apiserver middleware, cookie auth and internal service calls.

// defaultJwtSigningKey is the upstream hard-coded signing key.
const defaultJwtSigningKey = "secret"

// strongRootSecret is a production-shaped root secret (openssl rand -hex 32).
const strongRootSecret = "8aac552286da2f3495aead89fb05136a84dfa9827a9a801fa0ea19ff3b361026"

// forgeAdminTokenWithDefaultKey builds an HS256 token carrying admin-looking
// claims, signed with the publicly known default key — exactly what an
// attacker crafts without any knowledge of the deployment.
func forgeAdminTokenWithDefaultKey(t *testing.T) string {
	t.Helper()
	token := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, jwtLib.MapClaims{
		"uid":  "1",
		"name": "admin",
		"iss":  "actiontech dms",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(defaultJwtSigningKey))
	if err != nil {
		t.Fatalf("failed to forge token: %v", err)
	}
	return tokenStr
}

// restoreSigningState resets the package-global signing key and default DMS
// token after a test mutated them.
func restoreSigningState(t *testing.T) {
	t.Helper()
	origKey := dmsCommonV1.JwtSigningKey
	origToken := DefaultDMSToken
	t.Cleanup(func() {
		dmsCommonV1.JwtSigningKey = origKey
		DefaultDMSToken = origToken
	})
}

// A token forged with the default key must be rejected once a real root
// secret is configured, while tokens signed under the derived key still pass.
func TestForgedDefaultKeyTokenRejected(t *testing.T) {
	restoreSigningState(t)

	if err := ResetJWTSigningKeyAndDefaultToken(strongRootSecret); err != nil {
		t.Fatalf("failed to reset signing key with a strong root secret: %v", err)
	}

	// the forged default-key token must not pass the parse path
	if _, err := jwt.ParseUidFromJwtTokenStr(forgeAdminTokenWithDefaultKey(t)); err == nil {
		t.Fatal("admin token forged with the publicly known default key \"secret\" was accepted; JWT signing key derivation is broken (CVE-2025-15107)")
	}

	// control: a token signed with the current (derived) key must still pass
	signed, err := jwt.GenJwtToken(jwt.WithUserId("1"))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	uid, err := jwt.ParseUidFromJwtTokenStr(signed)
	if err != nil || uid != "1" {
		t.Fatalf("legitimately signed token must parse: uid=%q err=%v", uid, err)
	}
}

// The production incident configuration: secret_key left empty. The assembly
// must refuse instead of silently running on the default key.
func TestEmptySecretKeyRefused(t *testing.T) {
	restoreSigningState(t)

	if err := ResetJWTSigningKeyAndDefaultToken(""); err == nil {
		t.Fatal("empty secret_key was accepted; the assembly must fail instead of falling back to the publicly known default key (CVE-2025-15107)")
	}
}

// Even if someone configures secret_key: "secret" verbatim, the derived
// signing key must differ from the raw default key, so default-key forgeries
// stay rejected (defense in depth).
func TestDefaultKeyAsRootSecretStillRejected(t *testing.T) {
	restoreSigningState(t)

	if err := ResetJWTSigningKeyAndDefaultToken(defaultJwtSigningKey); err != nil {
		t.Fatalf("failed to reset signing key: %v", err)
	}

	if _, err := jwt.ParseUidFromJwtTokenStr(forgeAdminTokenWithDefaultKey(t)); err == nil {
		t.Fatal("admin token forged with the default key was accepted although the key was configured as root secret; the signing key must be derived, not used verbatim (CVE-2025-15107)")
	}
}
