package user

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
)

// The event type, the payload names and the unique constraint type are durable: changing one orphans
// stored events, or lets a token that was already used be used again.
func TestMachineFederatedCredentialExchangedEvent_durableNames(t *testing.T) {
	assert.Equal(t, eventstore.EventType("user.machine.federated_credential_ixcans_fork.exchanged"), MachineFederatedCredentialExchangedEventType)
	assert.Equal(t, "user_federated_credential_assertion_ixcans_fork", FederatedCredentialAssertionUniqueType)

	event := NewMachineFederatedCredentialExchangedEvent(context.Background(), &NewAggregate("user1", "org1").Aggregate, "V2_session1",
		&domain.FederatedCredentialExchange{
			CredentialID:  "cred1",
			UserID:        "user1",
			ResourceOwner: "org1",
			Issuer:        "https://issuer.example.com",
			Subject:       "repo:example/app:ref:refs/heads/main",
			SubjectClaim:  "repository_id",
			SubjectValue:  "123456",
			TokenID:       "jti1",
			AssertionKey:  "1700000000:abcdef",
		})
	payload, err := json.Marshal(event.Payload())
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"credentialId": "cred1",
		"issuer": "https://issuer.example.com",
		"subject": "repo:example/app:ref:refs/heads/main",
		"subjectClaim": "repository_id",
		"subjectValue": "123456",
		"tokenId": "jti1",
		"assertionKey": "1700000000:abcdef",
		"oidcSessionId": "V2_session1"
	}`, string(payload))

	assert.Equal(t, []*eventstore.UniqueConstraint{
		eventstore.NewAddEventUniqueConstraint("user_federated_credential_assertion_ixcans_fork", "1700000000:abcdef",
			"Errors.User.Machine.FederatedCredential.AssertionAlreadyUsed"),
	}, event.UniqueConstraints())
}

// Decoded from its stored payload, the event keeps what it recorded.
func TestMachineFederatedCredentialExchangedEvent_jsonRoundTrip(t *testing.T) {
	stored := NewMachineFederatedCredentialExchangedEvent(context.Background(), &NewAggregate("user1", "org1").Aggregate, "V2_session1",
		&domain.FederatedCredentialExchange{
			CredentialID: "cred1",
			Issuer:       "https://issuer.example.com",
			SubjectClaim: "sub",
			SubjectValue: "workload",
			AssertionKey: "1700000000:abcdef",
		})
	data, err := json.Marshal(stored.Payload())
	require.NoError(t, err)

	read := new(MachineFederatedCredentialExchangedEvent)
	require.NoError(t, json.Unmarshal(data, read))
	assert.Equal(t, "cred1", read.CredentialID)
	assert.Equal(t, "https://issuer.example.com", read.Issuer)
	assert.Equal(t, "", read.Subject)
	assert.Equal(t, "sub", read.SubjectClaim)
	assert.Equal(t, "workload", read.SubjectValue)
	assert.Equal(t, "", read.TokenID)
	assert.Equal(t, "V2_session1", read.OIDCSessionID)
}
