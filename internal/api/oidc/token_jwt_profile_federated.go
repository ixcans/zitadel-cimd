package oidc

import (
	"context"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// federatedCredentialJWTProfile handles a JWT-profile grant whose assertion a foreign issuer signed
// for a federated credential of a machine user (see federatedCredentialExchanger). It reports
// handled false for every other assertion, which the grant's key path then handles unchanged.
//
// An accepted assertion yields the same machine token the key path issues (the same client, scopes,
// audience and token type of the machine user), with three differences: the session's
// authentication method is domain.UserAuthMethodTypeFederatedCredential, the access token lives at
// most the credential's cap, and the session's push carries the exchanged event, which records the
// workload and makes the assertion single use.
func (s *Server) federatedCredentialJWTProfile(ctx context.Context, r *op.Request[oidc.JWTProfileGrantRequest]) (handled bool, _ *op.Response, err error) {
	match, err := s.federatedCredentials.match(ctx, r.Data.Assertion)
	if err != nil {
		return true, nil, err
	}
	if match == nil {
		return false, nil, nil
	}

	user, err := s.query.GetUserByIDWithResourceOwner(ctx, false, match.exchange.UserID, match.exchange.ResourceOwner)
	if err != nil {
		if zerrors.IsNotFound(err) {
			return true, nil, invalidFederatedAssertion(ctx, err, "the machine user of the federated credential does not exist")
		}
		return true, nil, err
	}
	if user.Type != domain.UserTypeMachine || user.Machine == nil {
		return true, nil, invalidFederatedAssertion(ctx, nil, "the user of the federated credential is not a machine user")
	}
	tokenLifetime := match.credential.MaxTokenLifetime
	client := &clientCredentialsClient{
		clientID:        user.Username,
		userID:          user.ID,
		resourceOwner:   user.ResourceOwner,
		tokenType:       user.Machine.AccessTokenType,
		idTokenLifeTime: min(s.defaultIdTokenLifetime, tokenLifetime),
	}
	scope, err := op.ValidateAuthReqScopes(client, r.Data.Scope)
	if err != nil {
		return true, nil, err
	}
	scope, err = s.checkOrgScopes(ctx, client.resourceOwner, scope)
	if err != nil {
		return true, nil, err
	}

	session, err := s.command.CreateOIDCSession(ctx,
		client.userID,
		client.resourceOwner,
		client.clientID,
		"", // backChannelLogoutURI not needed for service account session
		scope,
		domain.AddAudScopeToAudience(ctx, nil, r.Data.Scope),
		[]domain.UserAuthMethodType{domain.UserAuthMethodTypeFederatedCredential},
		time.Now(),
		"",
		nil,
		nil,
		domain.TokenReasonJWTProfile,
		nil,
		false,
		"",
		domain.OIDCResponseTypeUnspecified,
		command.WithMaxAccessTokenLifetime(tokenLifetime),
		command.WithFederatedCredentialExchange(match.exchange),
	)
	if zerrors.IsErrorAlreadyExists(err) {
		// The exchanged event's unique constraint: this assertion was exchanged before.
		return true, nil, invalidFederatedAssertion(ctx, err, "assertion was already used")
	}
	if err != nil {
		return true, nil, err
	}
	resp, err := response(s.accessTokenResponseFromSession(ctx, client, session, "", "", false, true, true, false))
	return true, resp, err
}
