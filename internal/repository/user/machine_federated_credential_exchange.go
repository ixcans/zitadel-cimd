package user

import (
	"context"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
)

// MachineFederatedCredentialExchangedEventType records that a token of a foreign issuer was
// exchanged for a machine token of the user (see domain.FederatedCredentialExchange). Like the
// other federated credential events it carries the fork-local suffix.
const MachineFederatedCredentialExchangedEventType = machineFederatedCredentialEventPrefix + "exchanged"

// FederatedCredentialAssertionUniqueType is the unique constraint type that makes a presented token
// single use: the exchanged event adds the token's key (domain.FederatedCredentialAssertionKey), in
// the same transaction as the session it issues, so a second exchange of the same token fails on
// every server. The constraints stay until the instance is removed.
const FederatedCredentialAssertionUniqueType = "user_federated_credential_assertion_ixcans_fork"

func init() {
	eventstore.RegisterFilterEventMapper(AggregateType, MachineFederatedCredentialExchangedEventType, eventstore.GenericEventMapper[MachineFederatedCredentialExchangedEvent])
}

// MachineFederatedCredentialExchangedEvent names the workload that authenticated (the issuer and
// the subject of its token), the credential that accepted it, and the OIDC session that was issued
// to the machine user in exchange. The session ID is the prefix of the issued token's ID, so the
// token leads to this record.
type MachineFederatedCredentialExchangedEvent struct {
	eventstore.BaseEvent `json:"-"`

	CredentialID  string `json:"credentialId"`
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject,omitempty"`
	SubjectClaim  string `json:"subjectClaim"`
	SubjectValue  string `json:"subjectValue"`
	TokenID       string `json:"tokenId,omitempty"`
	AssertionKey  string `json:"assertionKey"`
	OIDCSessionID string `json:"oidcSessionId"`
}

func (e *MachineFederatedCredentialExchangedEvent) SetBaseEvent(event *eventstore.BaseEvent) {
	e.BaseEvent = *event
}

func (e *MachineFederatedCredentialExchangedEvent) Payload() interface{} {
	return e
}

func (e *MachineFederatedCredentialExchangedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return []*eventstore.UniqueConstraint{
		eventstore.NewAddEventUniqueConstraint(
			FederatedCredentialAssertionUniqueType,
			e.AssertionKey,
			"Errors.User.Machine.FederatedCredential.AssertionAlreadyUsed",
		),
	}
}

func NewMachineFederatedCredentialExchangedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	oidcSessionID string,
	exchange *domain.FederatedCredentialExchange,
) *MachineFederatedCredentialExchangedEvent {
	return &MachineFederatedCredentialExchangedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			MachineFederatedCredentialExchangedEventType,
		),
		CredentialID:  exchange.CredentialID,
		Issuer:        exchange.Issuer,
		Subject:       exchange.Subject,
		SubjectClaim:  exchange.SubjectClaim,
		SubjectValue:  exchange.SubjectValue,
		TokenID:       exchange.TokenID,
		AssertionKey:  exchange.AssertionKey,
		OIDCSessionID: oidcSessionID,
	}
}
