package command

import "time"

// OIDCSessionOption bounds the tokens of an OIDC session more tightly than the instance settings
// do, for a caller whose client must not receive what the instance grants by default.
type OIDCSessionOption func(*oidcSessionOptions)

type oidcSessionOptions struct {
	maxAccessTokenLifetime time.Duration
}

// WithMaxAccessTokenLifetime caps the lifetime of the access token issued with the session at
// limit. The lifetime of the instance settings (or the system default) stays in force when it is
// shorter. A limit that is not positive caps nothing.
func WithMaxAccessTokenLifetime(limit time.Duration) OIDCSessionOption {
	return func(o *oidcSessionOptions) {
		o.maxAccessTokenLifetime = limit
	}
}

// applyOptions bounds the token lifetimes of c by opts. It runs after the lifetimes are read from
// the instance settings and before any token is added, so the stored token expiration and the
// token handed to the client agree.
func (c *OIDCSessionEvents) applyOptions(opts []OIDCSessionOption) {
	var options oidcSessionOptions
	for _, opt := range opts {
		opt(&options)
	}
	if options.maxAccessTokenLifetime > 0 && c.accessTokenLifetime > options.maxAccessTokenLifetime {
		c.accessTokenLifetime = options.maxAccessTokenLifetime
	}
}
