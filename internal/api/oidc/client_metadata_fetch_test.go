package oidc

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/cache/connector/noop"
	"github.com/zitadel/zitadel/internal/publicfetch"
)

// TestClientIDMetadataResolver_PublicOnlyClient resolves through the client the server uses in
// production. A document served from a loopback address, or from any port but the standard https
// port, is refused before anything reaches the server that serves it.
func TestClientIDMetadataResolver_PublicOnlyClient(t *testing.T) {
	ctx := testResolverContext()
	server := newMetadataServer(t, http.StatusOK, "", func(clientID string) clientRegistrationRequest {
		return clientRegistrationRequest{RedirectURIs: []string{clientID + "/callback"}, TokenEndpointAuthMethod: "none"}
	})

	for name, clientID := range map[string]string{
		"loopback address on a random port":   server.URL + testClientIDPath,
		"hostname on a non-standard port":     "https://client.example.com:8443/client",
		"hostname on the plain http port":     "https://client.example.com:80/client",
		"loopback address on the https port":  "https://127.0.0.1/client",
		"unique-local address":                "https://[fd00::1]/client",
		"translated link-local metadata host": "https://[64:ff9b::a9fe:a9fe]/client",
	} {
		t.Run(name, func(t *testing.T) {
			resolver := newClientIDMetadataResolver(publicfetch.NewClient(), clientIDMetadataAllowlist{allowAny: true},
				noop.NewCache[clientIDMetadataCacheIndex, string, *clientIDMetadataCacheEntry](), time.Hour, time.Hour, nil)

			_, err := resolver.ResolveClient(ctx, clientID)
			assertInvalidClient(t, err)
			require.Equal(t, int32(0), server.hits.Load(), "nothing may reach the document server")
		})
	}

	t.Run("the redirect policy of the resolver is kept", func(t *testing.T) {
		resolver := newClientIDMetadataResolver(publicfetch.NewClient(), clientIDMetadataAllowlist{allowAny: true}, nil, time.Hour, time.Hour, nil)
		assert.ErrorIs(t, resolver.httpClient.CheckRedirect(nil, nil), http.ErrUseLastResponse)
	})
}
