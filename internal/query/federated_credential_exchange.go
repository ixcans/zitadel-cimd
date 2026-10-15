package query

import (
	"context"

	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
	"github.com/zitadel/zitadel/internal/query/projection"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
)

// EnabledFederatedCredentialsByIssuer returns the enabled federated credentials of the instance
// whose issuer is exactly issuer, for the exchange at the token endpoint. It brings the read model
// up to date first, so that a credential disabled, changed or removed a moment ago is not used, and
// fails if it cannot: a stale read could accept a token a credential no longer allows.
func (q *Queries) EnabledFederatedCredentialsByIssuer(ctx context.Context, issuer string) (_ []*FederatedCredential, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	ctx, err = projection.FederatedCredentialProjection.Trigger(ctx, handler.WithAwaitRunning())
	if err != nil {
		return nil, err
	}
	issuerQuery, err := NewFederatedCredentialIssuerSearchQuery(issuer)
	if err != nil {
		return nil, err
	}
	enabledQuery, err := NewFederatedCredentialEnabledSearchQuery()
	if err != nil {
		return nil, err
	}
	credentials, err := q.SearchFederatedCredentials(ctx, &FederatedCredentialSearchQueries{
		Queries: []SearchQuery{issuerQuery, enabledQuery},
	}, nil)
	if err != nil {
		return nil, err
	}
	return credentials.FederatedCredentials, nil
}
