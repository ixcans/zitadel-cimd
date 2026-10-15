package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/cache/connector/noop"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
)

// TestClientIDMetadataDocumentClient_DeviceFlowRefused drives both entry points of the device
// authorization grant (RFC 8628) through the protocol layer's HTTP routes, with the client
// resolved from its metadata document by Server.VerifyClient, exactly as a request from the
// network is handled:
//
//   - the device authorization request (RFC 8628, section 3.1), which carries no grant_type, so the
//     routes' generic grant check does not apply and checkDeviceAuthorizationGrant in
//     Server.DeviceAuthorization refuses it;
//   - the device_code grant at the token endpoint (section 3.4), refused by the routes' grant check
//     before any device code is looked up.
//
// Both are refused with unauthorized_client, so no user code is ever issued for such a client and
// no device code can be redeemed by it. A consent step in a login UI does not cover the device
// flow, so these refusals are its whole guard.
func TestClientIDMetadataDocumentClient_DeviceFlowRefused(t *testing.T) {
	document := newMetadataServer(t, http.StatusOK, "", func(clientID string) clientRegistrationRequest {
		return clientRegistrationRequest{
			RedirectURIs:            []string{clientID + "/callback"},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethod: "none",
		}
	})
	clientID := document.URL + testClientIDPath
	ctx := authz.NewMockContext("instance", "org", "",
		authz.WithMockClientIDMetadataDocument(true),
		authz.WithMockClientIDMetadataDocumentAllowAnyURL(true),
	)
	server := &Server{
		clientIDMetadataResolver: newTestResolver(document.URL, document.Client(), noop.NewCache[clientIDMetadataCacheIndex, string, *clientIDMetadataCacheEntry]()),
	}
	handler := op.RegisterServer(server, op.Endpoints{
		DeviceAuthorization: op.NewEndpoint("/oauth/v2/device_authorization"),
		Token:               op.NewEndpoint("/oauth/v2/token"),
	})
	post := func(t *testing.T, path string, form url.Values) *oidc.Error {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode())).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		oidcErr := new(oidc.Error)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), oidcErr), rec.Body.String())
		return oidcErr
	}

	t.Run("the client resolves, so a refusal below is the grant rule", func(t *testing.T) {
		client, err := server.VerifyClient(ctx, &op.Request[op.ClientCredentials]{
			Form: url.Values{},
			Data: &op.ClientCredentials{ClientID: clientID},
		})
		require.NoError(t, err)
		assert.Equal(t, clientID, client.GetID())
		assert.NotContains(t, client.GrantTypes(), oidc.GrantTypeDeviceCode)
	})

	t.Run("device authorization request is refused", func(t *testing.T) {
		oidcErr := post(t, "/oauth/v2/device_authorization", url.Values{
			"client_id": {clientID},
			"scope":     {"openid profile"},
		})
		assert.Equal(t, oidc.UnauthorizedClient, oidcErr.ErrorType, oidcErr.Description)
	})

	t.Run("device_code grant at the token endpoint is refused", func(t *testing.T) {
		oidcErr := post(t, "/oauth/v2/token", url.Values{
			"grant_type":  {string(oidc.GrantTypeDeviceCode)},
			"device_code": {"a-device-code"},
			"client_id":   {clientID},
		})
		assert.Equal(t, oidc.UnauthorizedClient, oidcErr.ErrorType, oidcErr.Description)
	})
}

// TestCheckDeviceAuthorizationGrant pins the rule Server.DeviceAuthorization applies: only a client
// holding the device code grant may start a device authorization.
func TestCheckDeviceAuthorizationGrant(t *testing.T) {
	tests := []struct {
		name       string
		clientID   string
		grantTypes []domain.OIDCGrantType
		wantErr    bool
	}{
		{"metadata document client", "https://app.example.com/client", clientIDMetadataGrantTypes, true},
		{"registered client with the device code grant", "312909075212468632", []domain.OIDCGrantType{domain.OIDCGrantTypeDeviceCode}, false},
		{"registered client without it", "312909075212468632", []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode, domain.OIDCGrantTypeRefreshToken}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := ClientFromBusiness(&query.OIDCClient{ClientID: tt.clientID, GrantTypes: tt.grantTypes}, "", "")
			err := checkDeviceAuthorizationGrant(client)
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			var oidcErr *oidc.Error
			require.ErrorAs(t, err, &oidcErr)
			assert.Equal(t, oidc.UnauthorizedClient, oidcErr.ErrorType)
		})
	}
}
