package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// UserAuthMethodTypeFederatedCredential is the authentication method of a session whose machine
// user was authenticated by a token of a foreign issuer that one of its federated credentials
// accepted (see FederatedCredential), and not by a key the machine user holds
// (UserAuthMethodTypePrivateKey).
//
// The value is stored in the session events. It lies far outside the sequence of upstream methods,
// so that a method upstream adds later can never take it.
const UserAuthMethodTypeFederatedCredential UserAuthMethodType = 1001

// FederatedCredentialExchange records one accepted exchange of a foreign token for a machine
// token: which credential accepted which workload, and as which machine user.
type FederatedCredentialExchange struct {
	// CredentialID is the ID of the federated credential that accepted the token.
	CredentialID string
	// UserID and ResourceOwner identify the machine user the token was mapped to.
	UserID        string
	ResourceOwner string
	// Issuer is the token's iss claim.
	Issuer string
	// Subject is the token's sub claim; empty if the token has none.
	Subject string
	// SubjectClaim is the claim the credential's subject rule matched, and SubjectValue its value.
	SubjectClaim string
	SubjectValue string
	// TokenID is the token's jti claim; empty if the token has none.
	TokenID string
	// AssertionKey identifies the token for its single use; see FederatedCredentialAssertionKey.
	AssertionKey string
}

// FederatedCredentialAssertionKey identifies a presented token, so that it is accepted once only.
//
// A token with a jti is identified by its issuer and jti. A token without one is identified by its
// signing input in canonical form (its header and payload, each encoded in canonical base64url),
// never by the token as presented: an ECDSA signature can be rewritten into a second valid
// signature of the same content, and a base64url segment can be spelled differently without
// changing what it decodes to, so two different strings can carry the same signed token. The
// decoded header and payload cannot be changed without breaking the signature.
//
// The key begins with the token's expiration in Unix seconds, so that the keys of tokens that can
// no longer be accepted can be found without reading the tokens. It contains only digits, a colon
// and lower-case hexadecimal digits.
func FederatedCredentialAssertionKey(issuer, tokenID, signingInput string, expiration time.Time) string {
	hash := sha256.New()
	if tokenID != "" {
		hash.Write([]byte("jti\x00"))
		hash.Write([]byte(issuer))
		hash.Write([]byte{0})
		hash.Write([]byte(tokenID))
	} else {
		hash.Write([]byte("jws\x00"))
		hash.Write([]byte(signingInput))
	}
	return strconv.FormatInt(expiration.Unix(), 10) + ":" + hex.EncodeToString(hash.Sum(nil))
}

// FederatedCredentialKeyAlgorithm returns the one algorithm of FederatedCredentialAlgorithms that
// key (a public key of a JSON Web Key) can verify: RS256 for RSA of at least 2048 bits, ES256 for
// P-256, EdDSA for Ed25519. It returns "" for any other key.
func FederatedCredentialKeyAlgorithm(key any) string {
	return federatedCredentialKeyAlgorithm(key)
}
