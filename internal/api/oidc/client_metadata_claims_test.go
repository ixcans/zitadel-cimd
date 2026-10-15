package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/cache/connector/noop"
	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/domain"
)

// TestClientIDMetadataDocumentClient_TokenClaims pins what the tokens of a client resolved from its
// metadata document say about the client, with the client exactly as the resolver produces it and
// the token builders the code exchange and refresh grants use: the client ID URL is the client_id
// claim of both tokens and the azp of the ID token; the audience is the client alone for an
// identity-only request and the granted project otherwise (the ID token adds the client, as OpenID
// Connect requires); no role claim is asserted, because the resolved client asks for none; the ID
// token lives at most five minutes.
func TestClientIDMetadataDocumentClient_TokenClaims(t *testing.T) {
	const (
		issuer          = "https://issuer.example.com"
		listedProjectID = "340000000000000001"
	)
	document := newMetadataServer(t, http.StatusOK, "", func(origin string) clientRegistrationRequest {
		return clientRegistrationRequest{
			RedirectURIs:            []string{origin + "/callback"},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethod: "none",
		}
	})
	clientID := document.URL + testClientIDPath
	ctx := op.ContextWithIssuer(authz.NewMockContext("instance", "org", "",
		authz.WithMockClientIDMetadataDocument(true),
		authz.WithMockClientIDMetadataDocumentAllowAnyURL(true),
	), issuer)
	resolver := newTestResolver(document.URL, document.Client(), noop.NewCache[clientIDMetadataCacheIndex, string, *clientIDMetadataCacheEntry]())
	resolved, err := resolver.ResolveClient(ctx, clientID)
	require.NoError(t, err)
	client, ok := ClientFromBusiness(resolved, "", "").(*Client)
	require.True(t, ok)

	t.Run("the resolved client has no project and asks for no roles", func(t *testing.T) {
		assert.Empty(t, client.client.ProjectID)
		assert.False(t, client.client.ProjectRoleAssertion)
		assert.False(t, client.client.AccessTokenRoleAssertion)
		assert.False(t, client.client.IDTokenRoleAssertion)
		assert.False(t, client.client.IDTokenUserinfoAssertion)
		assert.Equal(t, op.AccessTokenTypeJWT, client.AccessTokenType())
	})

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	require.NoError(t, err)
	getSigner := func(context.Context) (jose.Signer, jose.SignatureAlgorithm, error) {
		return signer, jose.RS256, nil
	}
	// The user info getter asserts a role claim only when asked to, as the real one does, so a
	// role claim in a token means the caller asked for role assertion.
	getUserInfo := func(_ context.Context, roleAssertion bool, _ domain.TriggerType, _ *domain.TokenActor) (*oidc.UserInfo, error) {
		info := &oidc.UserInfo{Subject: "user1"}
		if roleAssertion {
			info.AppendClaims(ClaimProjectRoles, map[string]map[string]string{"admin": {"org": "org.example.com"}})
		}
		return info, nil
	}
	decode := func(t *testing.T, token string) map[string]any {
		t.Helper()
		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		claims := make(map[string]any)
		require.NoError(t, json.Unmarshal(payload, &claims))
		return claims
	}
	audience := func(claims map[string]any) []string {
		switch aud := claims["aud"].(type) {
		case string:
			return []string{aud}
		case []any:
			out := make([]string, len(aud))
			for i, a := range aud {
				out[i], _ = a.(string)
			}
			return out
		default:
			return nil
		}
	}
	assertNoRoles := func(t *testing.T, claims map[string]any) {
		t.Helper()
		for name := range claims {
			assert.NotContains(t, name, ":roles", "role claim %q", name)
		}
	}

	for _, tt := range []struct {
		name                string
		sessionAudience     []string
		wantAccessAudience  []string
		wantIDTokenAudience []string
	}{
		{"identity-only request", nil, []string{clientID}, []string{clientID}},
		{"request with a listed project audience", []string{listedProjectID}, []string{listedProjectID}, []string{listedProjectID, clientID}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			session := &command.OIDCSession{
				SessionID:  "sessionID",
				TokenID:    "V2_oidcSessionID-at_accessTokenID",
				ClientID:   clientID,
				UserID:     "user1",
				Audience:   tt.sessionAudience,
				Expiration: time.Now().Add(time.Hour),
				Scope:      []string{oidc.ScopeOpenID},
			}
			server := new(Server)

			accessToken, err := server.createJWT(ctx, client, session, getUserInfo, client.client.AccessTokenRoleAssertion, getSigner)
			require.NoError(t, err)
			accessClaims := decode(t, accessToken)
			assert.Equal(t, issuer, accessClaims["iss"])
			assert.Equal(t, "user1", accessClaims["sub"])
			assert.Equal(t, clientID, accessClaims["client_id"])
			assert.Equal(t, tt.wantAccessAudience, audience(accessClaims))
			assertNoRoles(t, accessClaims)

			idToken, _, err := server.createIDToken(ctx, client, getUserInfo, client.client.IDTokenRoleAssertion, getSigner,
				session.SessionID, accessToken, session.Audience, nil, time.Now(), "nonce", nil)
			require.NoError(t, err)
			idClaims := decode(t, idToken)
			assert.Equal(t, clientID, idClaims["azp"])
			assert.Equal(t, clientID, idClaims["client_id"])
			assert.Equal(t, tt.wantIDTokenAudience, audience(idClaims))
			assertNoRoles(t, idClaims)
			exp, iat := idClaims["exp"].(float64), idClaims["iat"].(float64)
			assert.LessOrEqual(t, exp-iat, clientIDMetadataMaxIDTokenLifetime.Seconds())
		})
	}
}
