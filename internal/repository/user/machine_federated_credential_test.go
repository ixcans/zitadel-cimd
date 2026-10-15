package user

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
)

// The event types and payload names are durable history: changing one orphans every stored event.
func TestMachineFederatedCredentialEvents_durableNames(t *testing.T) {
	assert.Equal(t, eventstore.EventType("user.machine.federated_credential_ixcans_fork.added"), MachineFederatedCredentialAddedEventType)
	assert.Equal(t, eventstore.EventType("user.machine.federated_credential_ixcans_fork.changed"), MachineFederatedCredentialChangedEventType)
	assert.Equal(t, eventstore.EventType("user.machine.federated_credential_ixcans_fork.removed"), MachineFederatedCredentialRemovedEventType)

	credential := &domain.FederatedCredential{
		Issuer:           "https://issuer.example.com",
		KeySource:        domain.FederatedCredentialKeySourceIssuerMetadata,
		Algorithms:       []string{"ES256"},
		Audience:         "aud",
		SubjectRule:      domain.FederatedCredentialSubjectRule{Claim: "sub", Exact: "workload"},
		ClaimConditions:  []domain.FederatedCredentialClaimCondition{{Claim: "env", Value: "prod"}},
		MaxTokenAge:      time.Minute,
		MaxTokenLifetime: 2 * time.Minute,
	}
	added, err := json.Marshal(NewMachineFederatedCredentialAddedEvent(context.Background(), &NewAggregate("user1", "org1").Aggregate, "cred1", credential).Payload())
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"credentialId": "cred1",
		"issuer": "https://issuer.example.com",
		"keySource": 1,
		"algorithms": ["ES256"],
		"audience": "aud",
		"subjectRule": {"claim": "sub", "exact": "workload"},
		"claimConditions": [{"claim": "env", "value": "prod"}],
		"maxTokenAge": 60000000000,
		"maxTokenLifetime": 120000000000
	}`, string(added))

	disabled := *credential
	disabled.Disabled = true
	disabled.ClaimConditions = nil
	changed, err := json.Marshal(NewMachineFederatedCredentialChangedEvent(context.Background(), &NewAggregate("user1", "org1").Aggregate, "cred1", credential, &disabled).Payload())
	require.NoError(t, err)
	assert.JSONEq(t, `{"credentialId": "cred1", "claimConditions": [], "disabled": true}`, string(changed))

	enabled, err := json.Marshal(NewMachineFederatedCredentialChangedEvent(context.Background(), &NewAggregate("user1", "org1").Aggregate, "cred1", &disabled, credential).Payload())
	require.NoError(t, err)
	assert.JSONEq(t, `{"credentialId": "cred1", "claimConditions": [{"claim": "env", "value": "prod"}], "disabled": false}`, string(enabled))

	removed, err := json.Marshal(NewMachineFederatedCredentialRemovedEvent(context.Background(), &NewAggregate("user1", "org1").Aggregate, "cred1").Payload())
	require.NoError(t, err)
	assert.JSONEq(t, `{"credentialId": "cred1"}`, string(removed))
}

func TestMachineFederatedCredentialChangedEvent_noChange(t *testing.T) {
	credential := &domain.FederatedCredential{Issuer: "https://issuer.example.com", Algorithms: []string{"ES256"}}
	same := *credential
	same.Algorithms = []string{"ES256"}
	assert.Nil(t, NewMachineFederatedCredentialChangedEvent(context.Background(), &NewAggregate("user1", "org1").Aggregate, "cred1", credential, &same))
}

func TestMachineFederatedCredentialChangedEvent_apply(t *testing.T) {
	before := &domain.FederatedCredential{
		Issuer:     "https://issuer.example.com",
		KeySource:  domain.FederatedCredentialKeySourcePinnedKeys,
		PinnedKeys: `{"keys":[]}`,
		Algorithms: []string{"ES256"},
		Audience:   "aud",
	}
	after := *before
	after.KeySource = domain.FederatedCredentialKeySourceIssuerMetadata
	after.PinnedKeys = ""
	after.Algorithms = []string{"RS256", "EdDSA"}
	after.MaxTokenLifetime = time.Minute
	event := NewMachineFederatedCredentialChangedEvent(context.Background(), &NewAggregate("user1", "org1").Aggregate, "cred1", before, &after)
	require.NotNil(t, event)

	// round trip through the stored form, as the write model and the projection read it
	data, err := json.Marshal(event.Payload())
	require.NoError(t, err)
	stored := new(MachineFederatedCredentialChangedEvent)
	require.NoError(t, json.Unmarshal(data, stored))

	got := *before
	stored.Apply(&got)
	assert.Equal(t, after, got)
}
