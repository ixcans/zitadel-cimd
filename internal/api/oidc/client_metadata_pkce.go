package oidc

import (
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// PKCE rule for clients resolved from a Client ID Metadata Document. Such a client is public (it
// has no secret) and is described by a document anyone can publish, so the authorization code is
// its only credential at the token endpoint. Proof Key for Code Exchange (RFC 7636) binds the code
// to the client that started the request, which OAuth 2.0 Security Best Current Practice (RFC 9700,
// section 2.1.1) requires of public clients. The protocol layer enforces a code verifier only when
// the authorization request carried a challenge, so the requirement is applied here:
//
//   - the authorization request must carry a code_challenge with the S256 method; "plain" (also
//     the method when none is named) puts the verifier itself into the front-channel request, so
//     whoever can read that request can redeem a stolen code, and any client that can hash can use
//     S256 (RFC 7636, section 4.2);
//   - the token request of such a client is refused when its authorization request carries no S256
//     challenge, so a request that reached the token endpoint any other way cannot skip it.
//
// Registered and dynamically registered clients are not affected.

// cimdPKCEViolation returns why the PKCE parameters of an authorization request of clientID break
// the rule above, or "" when they satisfy it or the client is not resolved from a document.
func cimdPKCEViolation(clientID, codeChallenge string, method oidc.CodeChallengeMethod) string {
	if !isClientIDMetadataDocumentClient(clientID) {
		return ""
	}
	if codeChallenge == "" {
		return "code_challenge is required for a client id metadata document client"
	}
	if method != oidc.CodeChallengeMethodS256 {
		return "code_challenge_method must be S256 for a client id metadata document client"
	}
	return ""
}

// checkClientIDMetadataDocumentAuthRequestPKCE applies the rule to an authorization request. Its
// error is meant to be redirected to the (already validated) redirect URI.
func checkClientIDMetadataDocumentAuthRequestPKCE(clientID string, req *oidc.AuthRequest) error {
	if violation := cimdPKCEViolation(clientID, req.CodeChallenge, req.CodeChallengeMethod); violation != "" {
		return oidc.ErrInvalidRequest().WithDescription("%s", violation)
	}
	return nil
}

// checkClientIDMetadataDocumentCodePKCE applies the rule at the token endpoint to the challenge
// stored with the authorization request the code was issued for.
func checkClientIDMetadataDocumentCodePKCE(clientID string, challenge *oidc.CodeChallenge) error {
	var (
		codeChallenge string
		method        oidc.CodeChallengeMethod
	)
	if challenge != nil {
		codeChallenge, method = challenge.Challenge, challenge.Method
	}
	if violation := cimdPKCEViolation(clientID, codeChallenge, method); violation != "" {
		return oidc.ErrInvalidGrant().WithDescription("%s", violation)
	}
	return nil
}
