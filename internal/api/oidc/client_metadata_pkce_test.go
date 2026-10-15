package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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

const (
	cimdTestPKCEClientID       = "https://app.example.com/oauth/client-metadata.json"
	cimdTestRegisteredClientID = "312909075212468632"
	// A code verifier is 43 to 128 characters (RFC 7636, section 4.1).
	cimdTestCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func TestCIMDPKCEViolation(t *testing.T) {
	challenge := oidc.NewSHACodeChallenge(cimdTestCodeVerifier)
	tests := []struct {
		name          string
		clientID      string
		codeChallenge string
		method        oidc.CodeChallengeMethod
		wantViolation bool
	}{
		{"metadata document client with S256", cimdTestPKCEClientID, challenge, oidc.CodeChallengeMethodS256, false},
		{"metadata document client without a challenge", cimdTestPKCEClientID, "", "", true},
		{"metadata document client with a method but no challenge", cimdTestPKCEClientID, "", oidc.CodeChallengeMethodS256, true},
		{"metadata document client with plain", cimdTestPKCEClientID, cimdTestCodeVerifier, oidc.CodeChallengeMethodPlain, true},
		// RFC 7636, section 4.3: a challenge without a method is plain.
		{"metadata document client with a challenge but no method", cimdTestPKCEClientID, challenge, "", true},
		{"metadata document client with an unknown method", cimdTestPKCEClientID, challenge, "S512", true},
		{"registered client without a challenge", cimdTestRegisteredClientID, "", "", false},
		{"registered client with plain", cimdTestRegisteredClientID, cimdTestCodeVerifier, oidc.CodeChallengeMethodPlain, false},
		{"http url client without a challenge", "http://app.example.com/client", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violation := cimdPKCEViolation(tt.clientID, tt.codeChallenge, tt.method)
			assert.Equal(t, tt.wantViolation, violation != "", violation)

			err := checkClientIDMetadataDocumentAuthRequestPKCE(tt.clientID, &oidc.AuthRequest{CodeChallenge: tt.codeChallenge, CodeChallengeMethod: tt.method})
			assertOIDCErrorType(t, tt.wantViolation, string(oidc.InvalidRequest), err)
		})
	}
}

// TestCodeExchangeComplianceChecker_clientIDMetadataDocumentPKCE pins the token endpoint half of the
// rule: the protocol layer checks a code verifier only against a stored challenge, so without the
// rule a code issued to a metadata document client without PKCE would be redeemed with no verifier.
func TestCodeExchangeComplianceChecker_clientIDMetadataDocumentPKCE(t *testing.T) {
	const redirectURI = "https://app.example.com/callback"
	s256 := &domain.OIDCCodeChallenge{Challenge: oidc.NewSHACodeChallenge(cimdTestCodeVerifier), Method: domain.CodeChallengeMethodS256}
	plain := &domain.OIDCCodeChallenge{Challenge: cimdTestCodeVerifier, Method: domain.CodeChallengeMethodPlain}
	publicClient := func(clientID string) *Client {
		client, ok := ClientFromBusiness(&query.OIDCClient{
			ClientID:       clientID,
			AuthMethodType: domain.OIDCAuthMethodTypeNone,
			GrantTypes:     clientIDMetadataGrantTypes,
		}, "", "").(*Client)
		require.True(t, ok)
		return client
	}
	exchangedAuthRequest := func(clientID string, challenge *domain.OIDCCodeChallenge) *command.AuthRequestWriteModel {
		return &command.AuthRequestWriteModel{
			ClientID:         clientID,
			RedirectURI:      redirectURI,
			CodeChallenge:    challenge,
			SessionID:        "sessionID",
			ResponseType:     domain.OIDCResponseTypeCode,
			AuthRequestState: domain.AuthRequestStateCodeExchanged,
		}
	}
	tests := []struct {
		name         string
		clientID     string
		challenge    *domain.OIDCCodeChallenge
		codeVerifier string
		wantErrType  string
	}{
		{"metadata document client, S256 and the right verifier", cimdTestPKCEClientID, s256, cimdTestCodeVerifier, ""},
		{"metadata document client, S256 and a wrong verifier", cimdTestPKCEClientID, s256, cimdTestCodeVerifier + "x", string(oidc.InvalidGrant)},
		{"metadata document client, S256 and no verifier", cimdTestPKCEClientID, s256, "", string(oidc.InvalidRequest)},
		{"metadata document client, no challenge and no verifier", cimdTestPKCEClientID, nil, "", string(oidc.InvalidGrant)},
		{"metadata document client, plain and the right verifier", cimdTestPKCEClientID, plain, cimdTestCodeVerifier, string(oidc.InvalidGrant)},
		{"registered public client, no challenge and no verifier", cimdTestRegisteredClientID, nil, "", ""},
		{"registered public client, plain and the right verifier", cimdTestRegisteredClientID, plain, cimdTestCodeVerifier, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := codeExchangeComplianceChecker(publicClient(tt.clientID), &oidc.AccessTokenRequest{
				RedirectURI:  redirectURI,
				CodeVerifier: tt.codeVerifier,
			})
			err := check(context.Background(), exchangedAuthRequest(tt.clientID, tt.challenge))
			assertOIDCErrorType(t, tt.wantErrType != "", tt.wantErrType, err)
		})
	}
}

// TestClientIDMetadataDocumentClient_AuthorizeRequiresPKCE drives the authorization endpoint
// through the protocol layer's HTTP routes, with the client resolved from its metadata document, and
// checks that a request without an S256 challenge is answered at the client's redirect URI with
// invalid_request, after every other check of the request has passed and before an auth request is
// created.
func TestClientIDMetadataDocumentClient_AuthorizeRequiresPKCE(t *testing.T) {
	document := newMetadataServer(t, http.StatusOK, "", func(origin string) clientRegistrationRequest {
		return clientRegistrationRequest{
			RedirectURIs:            []string{origin + "/callback"},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethod: "none",
		}
	})
	clientID := document.URL + testClientIDPath
	redirectURI := document.URL + "/callback"
	ctx := authz.NewMockContext("instance", "org", "",
		authz.WithMockClientIDMetadataDocument(true),
		authz.WithMockClientIDMetadataDocumentAllowAnyURL(true),
	)
	resolver := newTestResolver(document.URL, document.Client(), noop.NewCache[clientIDMetadataCacheIndex, string, *clientIDMetadataCacheEntry]())
	endpoints := op.Endpoints{Authorization: op.NewEndpoint("/oauth/v2/authorize")}
	provider, err := op.NewProvider(&op.Config{CodeMethodS256: true}, &OPStorage{clientIDMetadataResolver: resolver}, op.StaticIssuer("https://issuer.example.com"))
	require.NoError(t, err)
	server := &Server{
		LegacyServer:             op.NewLegacyServer(provider, endpoints),
		clientIDMetadataResolver: resolver,
	}
	handler := op.RegisterServer(server, endpoints)
	params := func(pkce url.Values) url.Values {
		values := url.Values{
			"client_id":     {clientID},
			"redirect_uri":  {redirectURI},
			"response_type": {"code"},
			"scope":         {"openid profile"},
			"state":         {"state-1"},
		}
		for key, value := range pkce {
			values[key] = value
		}
		return values
	}

	t.Run("a request with an S256 challenge passes the request checks and the rule", func(t *testing.T) {
		cr, err := server.VerifyAuthRequest(ctx, &op.Request[oidc.AuthRequest]{Data: &oidc.AuthRequest{
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			ResponseType:        oidc.ResponseTypeCode,
			Scopes:              oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
			CodeChallenge:       oidc.NewSHACodeChallenge(cimdTestCodeVerifier),
			CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		}})
		require.NoError(t, err)
		assert.Equal(t, clientID, cr.Client.GetID())
		assert.NoError(t, checkClientIDMetadataDocumentAuthRequestPKCE(cr.Client.GetID(), cr.Data))
	})

	for _, tt := range []struct {
		name string
		pkce url.Values
	}{
		{"without a challenge", nil},
		{"with the plain method", url.Values{"code_challenge": {cimdTestCodeVerifier}, "code_challenge_method": {"plain"}}},
		{"with a challenge but no method", url.Values{"code_challenge": {oidc.NewSHACodeChallenge(cimdTestCodeVerifier)}}},
	} {
		t.Run("a request "+tt.name+" is refused at the redirect URI", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/oauth/v2/authorize?"+params(tt.pkce).Encode(), nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
			location, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, redirectURI, location.Scheme+"://"+location.Host+location.Path)
			assert.Equal(t, string(oidc.InvalidRequest), location.Query().Get("error"))
			assert.Equal(t, "state-1", location.Query().Get("state"))
			assert.Contains(t, location.Query().Get("error_description"), "code_challenge")
		})
	}
}

func assertOIDCErrorType(t *testing.T, wantErr bool, wantType string, err error) {
	t.Helper()
	if !wantErr {
		assert.NoError(t, err)
		return
	}
	var oidcErr *oidc.Error
	require.ErrorAs(t, err, &oidcErr)
	assert.Equal(t, wantType, string(oidcErr.ErrorType), oidcErr.Description)
}
