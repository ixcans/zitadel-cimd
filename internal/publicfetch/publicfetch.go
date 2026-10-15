// Package publicfetch provides the HTTP client for documents that a caller names by URL and that
// must come from the public internet only, such as a client's metadata document or the published
// keys of a token issuer. Whoever sends such a URL chooses where ZITADEL connects, so the client
// must never reach the network ZITADEL itself runs in.
//
// The client connects only to public unicast addresses (IsPublicUnicast) on the standard https
// port (Port), over TLS. Every address is judged at dial time, on the address the connection is
// actually made to, after name resolution: a hostname that resolves, or re-resolves between two
// lookups, into a private or otherwise special range is refused, so DNS rebinding cannot get past
// the check. The rule is its own and does not depend on the operator's deny list
// (HTTPClient.DenyList), which also guards admin-defined targets such as Actions and is left as it
// is.
//
// The client never uses a proxy, because a dial-time check made against a proxy would judge the
// proxy and not the target, and it never follows a redirect: the response to the URL a caller
// named is the one it receives.
package publicfetch

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrDenied is wrapped by every error that refuses a URL or an address.
var ErrDenied = errors.New("not a public https destination")

const (
	// clientTimeout bounds a whole request when the caller's context does not bound it sooner.
	clientTimeout = 10 * time.Second
	dialTimeout   = 5 * time.Second
)

// NewClient returns an HTTP client that fetches from public https endpoints only (see the package
// documentation). Callers bound the response body they read and may set a shorter deadline through
// the request context. A caller may copy the client and replace CheckRedirect, but not Transport,
// which holds the address rule.
func NewClient() *http.Client {
	return &http.Client{
		Transport: newTransport(CheckAddress),
		Timeout:   clientTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// transport refuses a request whose URL is not a public https URL before anything is dialed, and
// judges every address it dials with checkAddress.
type transport struct {
	base *http.Transport
}

func newTransport(checkAddress func(netip.AddrPort) error) *transport {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			addr, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: unparsable address %q", ErrDenied, address)
			}
			return checkAddress(addr)
		},
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.DialContext = dialer.DialContext
	return &transport{base: base}
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := CheckURL(req.URL); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// CheckURL reports whether u may be fetched: an absolute https URL with a host, on the standard
// port (no port, or Port spelled out), and, when the host is an IP literal, a public unicast one.
// It runs before any connection; the address a hostname resolves to is judged at dial time.
func CheckURL(u *url.URL) error {
	if u == nil || !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: only https URLs are fetched", ErrDenied)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: the URL has no host", ErrDenied)
	}
	if port := u.Port(); port != "" && port != fmt.Sprint(Port) {
		return fmt.Errorf("%w: port %s is not %d", ErrDenied, port, Port)
	}
	if ip, err := netip.ParseAddr(host); err == nil && !IsPublicUnicast(ip) {
		return fmt.Errorf("%w: %s is not a public unicast address", ErrDenied, ip)
	}
	return nil
}
