package oidc

import (
	"slices"
	"time"

	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
)

// Token rules for clients resolved from a Client ID Metadata Document. Such a client is described
// by a document anyone can publish, so what it is issued is bounded more tightly than for a
// registered client:
//
//   - Its access tokens are signed JWTs, so a resource server verifies them by signature alone,
//     without an introspection credential.
//   - A signed token cannot be revoked before it expires, so its access tokens live at most
//     clientIDMetadataMaxAccessTokenLifetime and its ID tokens at most
//     clientIDMetadataMaxIDTokenLifetime, whatever the instance or the system configures. A
//     shorter configured lifetime still applies.
//   - It may use only the authorization code and refresh token grants. A document that declares
//     any other grant (implicit, device code, token exchange) does not resolve, so no other grant
//     can be used with a self-declared client.
//
// Registered and dynamically registered clients are not affected: their client IDs are generated
// and never an https URL, which only a client resolved from a document can have.
const (
	clientIDMetadataMaxAccessTokenLifetime = time.Hour
	clientIDMetadataMaxIDTokenLifetime     = 5 * time.Minute
)

// clientIDMetadataGrantTypes are the only grant types a document may declare.
var clientIDMetadataGrantTypes = []domain.OIDCGrantType{
	domain.OIDCGrantTypeAuthorizationCode,
	domain.OIDCGrantTypeRefreshToken,
}

// cimdGrantTypesAllowed reports whether every grant type a document declares is allowed for a
// client resolved from it.
func cimdGrantTypesAllowed(grantTypes []domain.OIDCGrantType) bool {
	for _, grantType := range grantTypes {
		if !slices.Contains(clientIDMetadataGrantTypes, grantType) {
			return false
		}
	}
	return true
}

// cimdTokenSettings returns the token lifetimes of a client resolved from a document, given the
// configured ones: each is capped, and a configured lifetime that is not positive falls back to
// the cap instead of issuing tokens that are already expired.
func cimdTokenSettings(accessTokenLifetime, idTokenLifetime time.Duration) *query.OIDCSettings {
	return &query.OIDCSettings{
		AccessTokenLifetime: capLifetime(accessTokenLifetime, clientIDMetadataMaxAccessTokenLifetime),
		IdTokenLifetime:     capLifetime(idTokenLifetime, clientIDMetadataMaxIDTokenLifetime),
	}
}

func capLifetime(configured, limit time.Duration) time.Duration {
	if configured <= 0 || configured > limit {
		return limit
	}
	return configured
}

// oidcSessionOptions returns the options an OIDC session for client is created or refreshed with.
// The access token lifetime of a session is read from the instance settings when the session is
// created or refreshed, not from the client, so the cap of a client resolved from a document is
// passed along here. Any other client gets no option and is issued tokens as before.
func oidcSessionOptions(client *Client) []command.OIDCSessionOption {
	if !isClientIDMetadataDocumentClient(client.client.ClientID) {
		return nil
	}
	return []command.OIDCSessionOption{command.WithMaxAccessTokenLifetime(clientIDMetadataMaxAccessTokenLifetime)}
}

// isClientIDMetadataDocumentClient reports whether clientID belongs to a client resolved from a
// document. The client of a token request has already been resolved, and only the resolver can
// produce a client whose ID is an https URL: registered applications get generated IDs.
func isClientIDMetadataDocumentClient(clientID string) bool {
	return domain.IsClientIDMetadataDocumentURL(clientID)
}
