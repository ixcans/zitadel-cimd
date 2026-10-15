package oidc

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/zitadel/internal/cache/connector/noop"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
)

func TestParseLoopbackRedirectURI(t *testing.T) {
	tests := []struct {
		uri  string
		want bool
	}{
		{"http://127.0.0.1:3000/callback", true},
		{"http://127.0.0.1/callback", true},
		{"http://127.0.0.1:3000", true},
		{"http://[::1]:3000/callback", true},
		{"http://[::1]/callback", true},
		{"http://localhost:8080/callback", true},
		{"https://127.0.0.1:3000/callback", false},
		{"https://localhost/callback", false},
		{"http://127.0.0.2:3000/callback", false},
		{"http://[0:0:0:0:0:0:0:1]:3000/callback", false},
		{"http://[::ffff:127.0.0.1]:3000/callback", false},
		{"http://localhost.:3000/callback", false},
		{"http://LOCALHOST:3000/callback", false},
		{"http://127.0.0.1.:3000/callback", false},
		{"http://user@127.0.0.1:3000/callback", false},
		{"http://127.0.0.1:3000@evil.example.com/callback", false},
		{"http://127.0.0.1:3000/callback#fragment", false},
		{"http://evil.example.com/callback", false},
		{"myapp://callback", false},
		{"http:127.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			_, ok := parseLoopbackRedirectURI(tt.uri)
			assert.Equal(t, tt.want, ok)
		})
	}
}

func TestCIMDRedirectURIs(t *testing.T) {
	clientURL := mustParseURL(t, "https://app.example.com/client")
	got := cimdRedirectURIs(clientURL, []string{
		"https://app.example.com/callback",
		"http://127.0.0.1:3000/callback",
		"http://[::1]/callback",
		"http://localhost:8080/callback",
		" http://127.0.0.1:4000/trimmed ",
		"https://evil.example.com/callback",
		"http://app.example.com/callback",
		"http://evil.example.com/callback",
		"https://127.0.0.1/callback",
		"myapp://callback",
		"http://127.0.0.1:3000/callback",
	})
	assert.Equal(t, []string{
		"https://app.example.com/callback",
		"http://127.0.0.1:3000/callback",
		"http://[::1]/callback",
		"http://localhost:8080/callback",
		"http://127.0.0.1:4000/trimmed",
	}, got)

	assert.Nil(t, cimdRedirectURIs(clientURL, []string{"myapp://callback", "http://evil.example.com/callback"}))
}

func TestCIMDRedirectURIAllowed(t *testing.T) {
	registered := []string{
		"https://app.example.com/callback",
		"http://127.0.0.1:3000/callback",
		"http://[::1]/v6",
		"http://localhost:8080/cb",
	}
	tests := []struct {
		name      string
		requested string
		want      bool
	}{
		{"listed https address", "https://app.example.com/callback", true},
		{"listed IPv4 loopback address", "http://127.0.0.1:3000/callback", true},
		{"IPv4 loopback on another port", "http://127.0.0.1:49152/callback", true},
		{"IPv4 loopback without a port", "http://127.0.0.1/callback", true},
		{"listed IPv6 loopback address", "http://[::1]/v6", true},
		{"IPv6 loopback on a port", "http://[::1]:49152/v6", true},
		{"listed localhost address", "http://localhost:8080/cb", true},

		{"loopback with another path", "http://127.0.0.1:49152/other", false},
		{"loopback with another path case", "http://127.0.0.1:3000/Callback", false},
		{"loopback with a query", "http://127.0.0.1:49152/callback?x=1", false},
		{"loopback with https", "https://127.0.0.1:3000/callback", false},
		{"IPv6 loopback where only IPv4 is listed for the path", "http://[::1]:3000/callback", false},
		{"IPv4 loopback where only IPv6 is listed for the path", "http://127.0.0.1:3000/v6", false},
		{"localhost on another port", "http://localhost:8081/cb", false},
		{"unlisted localhost address", "http://localhost:3000/callback", false},
		{"IP literal where only localhost is listed", "http://127.0.0.1:8080/cb", false},
		{"another loopback IPv4 address", "http://127.0.0.2:3000/callback", false},
		{"another spelling of the IPv6 loopback address", "http://[0:0:0:0:0:0:0:1]:3000/callback", false},
		{"loopback-looking userinfo", "http://127.0.0.1:3000@evil.example.com/callback", false},
		{"loopback with a fragment", "http://127.0.0.1:3000/callback#fragment", false},
		{"non-loopback http address", "http://evil.example.com/callback", false},
		{"http on the client origin", "http://app.example.com/callback", false},
		{"custom scheme", "myapp://callback", false},
		{"unlisted https address on the client origin", "https://app.example.com/other", false},
		{"https address with an explicit default port", "https://app.example.com:443/callback", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cimdRedirectURIAllowed(registered, tt.requested))
		})
	}
}

// TestClientIDMetadataResolver_LoopbackRedirects resolves a document that lists loopback addresses
// and runs an authorization request's redirect URI through both checks the authorization endpoint
// applies, in order: verifyClientIDMetadataRedirectURI (from Server.VerifyAuthRequest) and the
// protocol layer's op.ValidateAuthReqRedirectURI.
func TestClientIDMetadataResolver_LoopbackRedirects(t *testing.T) {
	ctx := testResolverContext()
	server := newMetadataServer(t, http.StatusOK, "", func(clientID string) clientRegistrationRequest {
		return clientRegistrationRequest{
			RedirectURIs: []string{
				clientID + "/callback",
				"http://127.0.0.1:3000/callback",
				"http://[::1]/callback",
				"http://localhost:8080/cb",
				"myapp://callback",
				"http://evil.example.com/callback",
			},
			TokenEndpointAuthMethod: "none",
		}
	})
	resolver := newTestResolver(server.URL, server.Client(), noop.NewCache[clientIDMetadataCacheIndex, string, *clientIDMetadataCacheEntry]())
	resolved, err := resolver.ResolveClient(ctx, server.URL+testClientIDPath)
	require.NoError(t, err)
	assert.Equal(t, domain.OIDCApplicationTypeNative, resolved.ApplicationType, "a client with loopback redirects is native")
	assert.Equal(t, []string{
		server.URL + "/callback",
		"http://127.0.0.1:3000/callback",
		"http://[::1]/callback",
		"http://localhost:8080/cb",
	}, resolved.RedirectURIs, "custom schemes and non-loopback http addresses are dropped")
	client := ClientFromBusiness(resolved, "", "")

	authorize := func(redirectURI string) error {
		if err := verifyClientIDMetadataRedirectURI(client, redirectURI); err != nil {
			return err
		}
		return op.ValidateAuthReqRedirectURI(client, redirectURI, oidc.ResponseTypeCode)
	}
	for _, uri := range []string{
		server.URL + "/callback",
		"http://127.0.0.1:3000/callback",
		"http://127.0.0.1:49152/callback",
		"http://127.0.0.1/callback",
		"http://[::1]:49152/callback",
		"http://localhost:8080/cb",
		url.QueryEscape("http://127.0.0.1:49152/callback"),
	} {
		t.Run("accepted "+uri, func(t *testing.T) {
			assert.NoError(t, authorize(uri))
		})
	}
	for _, uri := range []string{
		"http://localhost:49152/callback",
		"http://localhost:8081/cb",
		"https://localhost:3000/callback",
		"https://127.0.0.1:3000/callback",
		"http://127.0.0.1:49152/other",
		"http://127.0.0.2:3000/callback",
		"myapp://callback",
		"http://evil.example.com/callback",
		"https://evil.example.com/callback",
		server.URL + "/other",
	} {
		t.Run("refused "+uri, func(t *testing.T) {
			assert.Error(t, authorize(uri))
		})
	}

	t.Run("the protocol layer alone would accept another loopback host", func(t *testing.T) {
		// Its native loopback matching compares only the path and query, which is why the
		// stricter check runs first.
		assert.NoError(t, op.ValidateAuthReqRedirectURI(client, "http://localhost:49152/callback", oidc.ResponseTypeCode))
		assert.Error(t, verifyClientIDMetadataRedirectURI(client, "http://localhost:49152/callback"))
	})
}

func TestClientIDMetadataResolver_RedirectTypes(t *testing.T) {
	ctx := testResolverContext()
	resolve := func(t *testing.T, redirectURIs func(clientID string) []string) (*query.OIDCClient, error) {
		server := newMetadataServer(t, http.StatusOK, "", func(clientID string) clientRegistrationRequest {
			return clientRegistrationRequest{RedirectURIs: redirectURIs(clientID), TokenEndpointAuthMethod: "none"}
		})
		resolver := newTestResolver(server.URL, server.Client(), noop.NewCache[clientIDMetadataCacheIndex, string, *clientIDMetadataCacheEntry]())
		return resolver.ResolveClient(ctx, server.URL+testClientIDPath)
	}

	t.Run("same-origin only stays a web client", func(t *testing.T) {
		client, err := resolve(t, func(clientID string) []string { return []string{clientID + "/callback"} })
		require.NoError(t, err)
		assert.Equal(t, domain.OIDCApplicationTypeWeb, client.ApplicationType)
	})
	t.Run("loopback only resolves", func(t *testing.T) {
		client, err := resolve(t, func(string) []string { return []string{"http://127.0.0.1/callback"} })
		require.NoError(t, err)
		assert.Equal(t, domain.OIDCApplicationTypeNative, client.ApplicationType)
		assert.Equal(t, []string{"http://127.0.0.1/callback"}, client.RedirectURIs)
	})
	t.Run("custom scheme only is rejected", func(t *testing.T) {
		_, err := resolve(t, func(string) []string { return []string{"myapp://callback"} })
		assertInvalidClient(t, err)
	})
	t.Run("non-loopback http only is rejected", func(t *testing.T) {
		_, err := resolve(t, func(string) []string { return []string{"http://evil.example.com/callback"} })
		assertInvalidClient(t, err)
	})
}

func TestVerifyClientIDMetadataRedirectURI_otherClients(t *testing.T) {
	client := ClientFromBusiness(&query.OIDCClient{
		ClientID:     "312909075212468632",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}, "", "")
	assert.NoError(t, verifyClientIDMetadataRedirectURI(client, "http://localhost:49152/anything"),
		"a registered client is left to the protocol layer")
}
