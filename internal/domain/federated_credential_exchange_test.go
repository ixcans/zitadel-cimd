package domain

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederatedCredentialAssertionKey(t *testing.T) {
	exp := time.Unix(1700000600, 0)
	byJTI := FederatedCredentialAssertionKey("https://issuer.example.com", "jti1", "header.payload", exp)

	t.Run("the key begins with the expiration and holds only lower-case characters", func(t *testing.T) {
		assert.Regexp(t, regexp.MustCompile(`^1700000600:[0-9a-f]{64}$`), byJTI)
	})
	t.Run("a token with a jti is identified by issuer and jti, not by its content", func(t *testing.T) {
		assert.Equal(t, byJTI, FederatedCredentialAssertionKey("https://issuer.example.com", "jti1", "other.content", exp))
		assert.NotEqual(t, byJTI, FederatedCredentialAssertionKey("https://issuer.example.com", "jti2", "header.payload", exp))
		assert.NotEqual(t, byJTI, FederatedCredentialAssertionKey("https://other.example.com", "jti1", "header.payload", exp))
	})
	t.Run("a token without a jti is identified by its signing input", func(t *testing.T) {
		bySigningInput := FederatedCredentialAssertionKey("https://issuer.example.com", "", "header.payload", exp)
		assert.NotEqual(t, byJTI, bySigningInput)
		assert.Equal(t, bySigningInput, FederatedCredentialAssertionKey("https://other.example.com", "", "header.payload", exp),
			"the signing input contains the issuer already")
		assert.NotEqual(t, bySigningInput, FederatedCredentialAssertionKey("https://issuer.example.com", "", "header.payload2", exp))
	})
	t.Run("issuer and jti cannot be shifted into each other", func(t *testing.T) {
		assert.NotEqual(t,
			FederatedCredentialAssertionKey("https://issuer.example.com/a", "b", "", exp),
			FederatedCredentialAssertionKey("https://issuer.example.com", "a/b", "", exp))
	})
}

func TestFederatedCredentialKeyAlgorithm(t *testing.T) {
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ed, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	assert.Equal(t, "RS256", FederatedCredentialKeyAlgorithm(&rsa2048.PublicKey))
	assert.Equal(t, "", FederatedCredentialKeyAlgorithm(&rsa1024.PublicKey))
	assert.Equal(t, "ES256", FederatedCredentialKeyAlgorithm(&p256.PublicKey))
	assert.Equal(t, "", FederatedCredentialKeyAlgorithm(&p384.PublicKey))
	assert.Equal(t, "EdDSA", FederatedCredentialKeyAlgorithm(ed))
	assert.Equal(t, "", FederatedCredentialKeyAlgorithm([]byte("secret")))
}
