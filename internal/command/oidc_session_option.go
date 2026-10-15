package command

import (
	"context"
	"time"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/repository/user"
)

// OIDCSessionOption bounds the tokens of an OIDC session more tightly than the instance settings
// do, for a caller whose client must not receive what the instance grants by default, or records
// with the session how its user was authenticated.
type OIDCSessionOption func(*oidcSessionOptions)

type oidcSessionOptions struct {
	maxAccessTokenLifetime      time.Duration
	federatedCredentialExchange *domain.FederatedCredentialExchange
}

// WithMaxAccessTokenLifetime caps the lifetime of the access token issued with the session at
// limit. The lifetime of the instance settings (or the system default) stays in force when it is
// shorter. A limit that is not positive caps nothing.
func WithMaxAccessTokenLifetime(limit time.Duration) OIDCSessionOption {
	return func(o *oidcSessionOptions) {
		o.maxAccessTokenLifetime = limit
	}
}

// WithFederatedCredentialExchange records, in the same push as the session, that the session's
// machine user was authenticated by a token of a foreign issuer that one of its federated
// credentials accepted (user.MachineFederatedCredentialExchangedEvent). The event also makes the
// token single use: it carries a unique constraint on exchange.AssertionKey, so the push fails with
// an already-exists error, and no session is created, when the same token was exchanged before.
// exchange.UserID must be the session's user.
func WithFederatedCredentialExchange(exchange *domain.FederatedCredentialExchange) OIDCSessionOption {
	return func(o *oidcSessionOptions) {
		o.federatedCredentialExchange = exchange
	}
}

// applyOptions bounds the token lifetimes of c by opts and adds the events they ask for. It runs
// after the lifetimes are read from the instance settings and before any token is added, so the
// stored token expiration and the token handed to the client agree.
func (c *OIDCSessionEvents) applyOptions(ctx context.Context, opts []OIDCSessionOption) {
	var options oidcSessionOptions
	for _, opt := range opts {
		opt(&options)
	}
	if options.maxAccessTokenLifetime > 0 && c.accessTokenLifetime > options.maxAccessTokenLifetime {
		c.accessTokenLifetime = options.maxAccessTokenLifetime
	}
	if exchange := options.federatedCredentialExchange; exchange != nil {
		c.events = append(c.events, user.NewMachineFederatedCredentialExchangedEvent(ctx,
			&user.NewAggregate(exchange.UserID, exchange.ResourceOwner).Aggregate,
			c.oidcSessionWriteModel.AggregateID,
			exchange,
		))
	}
}
