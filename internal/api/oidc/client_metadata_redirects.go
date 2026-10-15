package oidc

import (
	"net/url"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Redirect URIs of clients resolved from a Client ID Metadata Document.
//
// A document may authorize redirects back to the origin that serves it (originMatchedURIs, the
// trust anchor) and, so that a desktop or command-line tool can receive the result on the
// person's own computer, to loopback addresses (RFC 8252, section 7.3):
//
//   - http://127.0.0.1:{port}/{path} and http://[::1]:{port}/{path}: an authorization request may
//     use any port, as a tool listens on whatever port is free; the scheme, the host and the path
//     (and query) must match a listed address.
//   - http://localhost:{port}/{path}: accepted only exactly as listed, port included, because the
//     name can resolve to something other than the loopback interface.
//
// Any other address that is not on the client_id's origin (another https host, any other http
// host, a custom scheme) is dropped from the document as before. A client that lists a loopback
// address is a native client, the type whose loopback redirects the protocol layer accepts.

const (
	loopbackIPv4 = "127.0.0.1"
	loopbackIPv6 = "::1"
	localhost    = "localhost"
)

// cimdRedirectURIs returns the redirect URIs of a document a client resolved from it may use:
// those on the client_id's origin, and loopback ones.
func cimdRedirectURIs(clientURL *url.URL, uris []string) []string {
	kept := originMatchedURIs(clientURL, uris)
	for _, raw := range trimSpaceSlice(uris) {
		if _, ok := parseLoopbackRedirectURI(raw); ok && !slices.Contains(kept, raw) {
			kept = append(kept, raw)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

// cimdHasLoopbackRedirectURI reports whether uris contains a loopback redirect URI.
func cimdHasLoopbackRedirectURI(uris []string) bool {
	return slices.ContainsFunc(uris, func(uri string) bool {
		_, ok := parseLoopbackRedirectURI(uri)
		return ok
	})
}

// cimdRedirectURIAllowed reports whether an authorization request of a client resolved from a
// document may use requested as its redirect URI, given the client's redirect URIs: a listed URI
// matches exactly, and a loopback IP literal matches a listed one that differs only in its port.
func cimdRedirectURIAllowed(registered []string, requested string) bool {
	if slices.Contains(registered, requested) {
		return true
	}
	requestedURL, ok := parseLoopbackRedirectURI(requested)
	if !ok || requestedURL.Hostname() == localhost {
		return false
	}
	for _, raw := range registered {
		listed, ok := parseLoopbackRedirectURI(raw)
		if ok && listed.Hostname() == requestedURL.Hostname() &&
			listed.EscapedPath() == requestedURL.EscapedPath() &&
			listed.RawQuery == requestedURL.RawQuery {
			return true
		}
	}
	return false
}

// parseLoopbackRedirectURI parses raw as a loopback redirect URI: the http scheme, the host
// 127.0.0.1, [::1] or localhost, an optional port, and no userinfo or fragment.
func parseLoopbackRedirectURI(raw string) (*url.URL, bool) {
	if strings.Contains(raw, "#") {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" {
		return nil, false
	}
	// The host must be spelled exactly as one of the three, so a listed address and a requested
	// one compare as written: no trailing dot, no other case, no other spelling of an address.
	switch u.Hostname() {
	case loopbackIPv4, localhost:
		if strings.HasPrefix(u.Host, "[") {
			return nil, false
		}
	case loopbackIPv6:
		if !strings.HasPrefix(u.Host, "["+loopbackIPv6+"]") {
			return nil, false
		}
	default:
		return nil, false
	}
	return u, true
}

// verifyClientIDMetadataRedirectURI applies the redirect rule above to an authorization request
// before the protocol layer validates it. It is needed because the protocol layer's own loopback
// matching for native clients compares only the path and query, so on its own it would let a
// listed 127.0.0.1 address admit localhost, https or another loopback host. Any other client is
// left to the protocol layer.
func verifyClientIDMetadataRedirectURI(client op.Client, redirectURI string) error {
	if !isClientIDMetadataDocumentClient(client.GetID()) {
		return nil
	}
	// The protocol layer unescapes the redirect URI before it compares it, so the same form is
	// judged here.
	uri, err := url.QueryUnescape(redirectURI)
	if err != nil || uri == "" {
		return oidc.ErrInvalidRequestRedirectURI().WithDescription("The redirect_uri is missing or malformed.")
	}
	if !cimdRedirectURIAllowed(client.RedirectURIs(), uri) {
		return oidc.ErrInvalidRequestRedirectURI().WithDescription("The requested redirect_uri is not listed in the client id metadata document.")
	}
	return nil
}
