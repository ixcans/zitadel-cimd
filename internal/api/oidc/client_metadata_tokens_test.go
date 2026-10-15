package oidc

import (
	"context"
	"encoding/json"
	"net/http"
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
	"github.com/zitadel/zitadel/internal/query"
)

func TestCIMDGrantTypesAllowed(t *testing.T) {
	tests := []struct {
		name       string
		grantTypes []domain.OIDCGrantType
		want       bool
	}{
		{"authorization code", []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode}, true},
		{"authorization code and refresh token", []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode, domain.OIDCGrantTypeRefreshToken}, true},
		{"implicit", []domain.OIDCGrantType{domain.OIDCGrantTypeImplicit}, false},
		{"device code", []domain.OIDCGrantType{domain.OIDCGrantTypeDeviceCode}, false},
		{"token exchange", []domain.OIDCGrantType{domain.OIDCGrantTypeTokenExchange}, false},
		{"an allowed grant does not admit a refused one", []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode, domain.OIDCGrantTypeTokenExchange}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cimdGrantTypesAllowed(tt.grantTypes))
		})
	}
}

func TestCIMDTokenSettings(t *testing.T) {
	tests := []struct {
		name                    string
		accessToken, idToken    time.Duration
		wantAccess, wantIDToken time.Duration
	}{
		{"longer configured lifetimes are capped", 12 * time.Hour, 12 * time.Hour, time.Hour, 5 * time.Minute},
		{"shorter configured lifetimes stay", 30 * time.Minute, 2 * time.Minute, 30 * time.Minute, 2 * time.Minute},
		{"lifetimes equal to the caps stay", time.Hour, 5 * time.Minute, time.Hour, 5 * time.Minute},
		{"unset lifetimes fall back to the caps", 0, 0, time.Hour, 5 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := cimdTokenSettings(tt.accessToken, tt.idToken)
			assert.Equal(t, tt.wantAccess, settings.AccessTokenLifetime)
			assert.Equal(t, tt.wantIDToken, settings.IdTokenLifetime)
		})
	}
}

// TestClientIDMetadataResolver_TokenRules resolves a document on a system whose configured token
// lifetimes are far longer than the caps, and checks what the resolved client is issued and which
// grants the token and device authorization endpoints admit for it (both check the client's grant
// types through op.ValidateGrantType before the request reaches ZITADEL).
func TestClientIDMetadataResolver_TokenRules(t *testing.T) {
	ctx := testResolverContext()
	server := newMetadataServer(t, http.StatusOK, "", func(clientID string) clientRegistrationRequest {
		return clientRegistrationRequest{
			RedirectURIs:            []string{clientID + "/callback"},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		}
	})
	resolver := newClientIDMetadataResolver(server.Client(), clientIDMetadataAllowlist{urls: []string{server.URL + "/"}},
		noop.NewCache[clientIDMetadataCacheIndex, string, *clientIDMetadataCacheEntry](), 12*time.Hour, 12*time.Hour, nil)

	resolved, err := resolver.ResolveClient(ctx, server.URL+testClientIDPath)
	require.NoError(t, err)
	client := ClientFromBusiness(resolved, "", "").(*Client)

	t.Run("signed access tokens", func(t *testing.T) {
		assert.Equal(t, domain.OIDCTokenTypeJWT, resolved.AccessTokenType)
		assert.Equal(t, op.AccessTokenTypeJWT, client.AccessTokenType())
	})
	t.Run("access token lifetime capped at one hour", func(t *testing.T) {
		assert.Equal(t, time.Hour, client.AccessTokenLifetime())
	})
	t.Run("ID token lifetime capped at five minutes", func(t *testing.T) {
		assert.Equal(t, 5*time.Minute, client.IDTokenLifetime())
	})
	t.Run("no role assertion", func(t *testing.T) {
		assert.False(t, resolved.AccessTokenRoleAssertion)
		assert.False(t, resolved.IDTokenRoleAssertion)
		assert.False(t, resolved.ProjectRoleAssertion)
	})
	t.Run("authorization code and refresh token grants work", func(t *testing.T) {
		assert.True(t, op.ValidateGrantType(client, oidc.GrantTypeCode))
		assert.True(t, op.ValidateGrantType(client, oidc.GrantTypeRefreshToken))
	})
	for _, grantType := range []oidc.GrantType{
		oidc.GrantTypeImplicit,
		oidc.GrantTypeDeviceCode,
		oidc.GrantTypeTokenExchange,
		oidc.GrantTypeClientCredentials,
		oidc.GrantTypeBearer,
	} {
		t.Run("grant "+string(grantType)+" is refused", func(t *testing.T) {
			assert.False(t, op.ValidateGrantType(client, grantType))
		})
	}
	t.Run("implicit response types are refused at the authorization endpoint", func(t *testing.T) {
		assert.Error(t, op.ValidateAuthReqResponseType(client, oidc.ResponseTypeIDTokenOnly))
		assert.Error(t, op.ValidateAuthReqResponseType(client, oidc.ResponseTypeIDToken))
		assert.NoError(t, op.ValidateAuthReqResponseType(client, oidc.ResponseTypeCode))
	})
}

// TestClientIDMetadataResolver_RefusedGrants pins that a document declaring a grant other than the
// authorization code and refresh token grants does not resolve, alone or next to an allowed one.
func TestClientIDMetadataResolver_RefusedGrants(t *testing.T) {
	ctx := testResolverContext()
	for name, document := range map[string]clientRegistrationRequest{
		"implicit": {
			GrantTypes:    []string{"implicit"},
			ResponseTypes: []string{"id_token"},
		},
		"implicit next to authorization code": {
			GrantTypes:    []string{"authorization_code", "implicit"},
			ResponseTypes: []string{"code", "id_token token"},
		},
		"device code": {
			GrantTypes: []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		},
		"token exchange": {
			GrantTypes: []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := newMetadataServer(t, http.StatusOK, "", func(clientID string) clientRegistrationRequest {
				document.RedirectURIs = []string{clientID + "/callback"}
				document.TokenEndpointAuthMethod = "none"
				return document
			})
			resolver := newTestResolver(server.URL, server.Client(), noop.NewCache[clientIDMetadataCacheIndex, string, *clientIDMetadataCacheEntry]())

			_, err := resolver.ResolveClient(ctx, server.URL+testClientIDPath)
			assertInvalidClient(t, err)
		})
	}
}

func TestOIDCSessionOptions(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		want     int
	}{
		{"client resolved from a document is capped", "https://app.example.com/client", 1},
		{"registered client is unchanged", "312909075212468632", 0},
		{"registered client with project suffix is unchanged", "312909075212468632@project", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{client: &query.OIDCClient{ClientID: tt.clientID}}
			assert.Len(t, oidcSessionOptions(client), tt.want)
		})
	}
}

// TestCreateJWT_clientIDMetadataDocument builds the access token of a client resolved from a
// document the way the token endpoint does (createJWT with the client's own role assertion and a
// user info built like Server.userInfo), for a user who holds roles in the audience project, and
// checks the claims a resource server verifies.
func TestCreateJWT_clientIDMetadataDocument(t *testing.T) {
	const issuer = "https://issuer.example.com"
	clientID := "https://app.example.com/client"
	resolved := &query.OIDCClient{
		ClientID:        clientID,
		AccessTokenType: domain.OIDCTokenTypeJWT,
		Settings:        cimdTokenSettings(12*time.Hour, 12*time.Hour),
	}
	client := ClientFromBusiness(resolved, "", "").(*Client)
	user := &query.OIDCUserInfo{
		User: &query.User{ID: "user"},
		Org:  &query.UserInfoOrg{ID: "400000000000000004", Name: "acme", PrimaryDomain: "acme.example.com"},
		UserGrants: []query.UserGrant{
			{ProjectID: cimdTestListedProject, Roles: []string{"admin"}, ResourceOwner: "400000000000000004", OrgPrimaryDomain: "acme.example.com"},
		},
	}
	instanceCtx := op.ContextWithIssuer(authz.NewMockContext("instance", "org", "", authz.WithMockProjectID(cimdTestInstanceProject)), issuer)

	tests := []struct {
		name         string
		requested    []string
		wantAudience []string
	}{
		{
			name:         "listed audience",
			requested:    []string{oidc.ScopeOpenID, ScopeProjectsRoles, ScopeProjectRolePrefix + "admin", cimdTestAudienceScope(cimdTestListedProject), oidc.ScopeOfflineAccess},
			wantAudience: []string{cimdTestListedProject},
		},
		{
			name:         "identity only",
			requested:    []string{oidc.ScopeOpenID, ScopeProjectsRoles},
			wantAudience: []string{clientID},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, audience, err := cimdScopeAndAudience(tt.requested, cimdTestInstanceProject, cimdTestListed)
			require.NoError(t, err)
			expiration := time.Now().Add(client.AccessTokenLifetime())
			session := &command.OIDCSession{
				TokenID:    "V2_oidcSessionID-at_accessTokenID",
				ClientID:   clientID,
				UserID:     "user",
				Audience:   audience,
				Expiration: expiration,
				Scope:      scope,
			}
			// Mirrors Server.userInfo for this client: no project, no project role assertion.
			getUserInfo := func(ctx context.Context, roleAssertion bool, _ domain.TriggerType, _ *domain.TokenActor) (*oidc.UserInfo, error) {
				roleAudience, requestedRoles := prepareRoles(ctx, scope, resolved.ProjectID, resolved.ProjectRoleAssertion, false)
				info := userInfoToOIDC(user, resolved.IDTokenUserinfoAssertion, scope, "")
				assertRoles(resolved.ProjectID, user, roleAudience, requestedRoles, roleAssertion, info)
				return info, nil
			}
			getSigner := func(context.Context) (jose.Signer, jose.SignatureAlgorithm, error) {
				return signer, jose.RS256, nil
			}

			token, err := (&Server{}).createJWT(instanceCtx, client, session, getUserInfo, resolved.AccessTokenRoleAssertion, getSigner)
			require.NoError(t, err)

			signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
			require.NoError(t, err)
			payload, err := signed.Verify(&privKey.PublicKey)
			require.NoError(t, err)
			claims := new(oidc.AccessTokenClaims)
			require.NoError(t, json.Unmarshal(payload, claims))

			assert.Equal(t, issuer, claims.Issuer)
			assert.Equal(t, "user", claims.Subject)
			assert.Equal(t, tt.wantAudience, []string(claims.Audience))
			assert.Equal(t, clientID, claims.ClientID)
			assert.Equal(t, session.TokenID, claims.JWTID)
			assert.WithinDuration(t, expiration, claims.Expiration.AsTime(), time.Second)
			assert.LessOrEqual(t, claims.Expiration.AsTime().Sub(claims.IssuedAt.AsTime()), time.Hour+time.Second)
			for claim := range claims.Claims {
				assert.NotContains(t, claim, ":roles", "role claim %s", claim)
				assert.NotEqual(t, ClaimUserMetaData, claim)
			}
		})
	}
}
