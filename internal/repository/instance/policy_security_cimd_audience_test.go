package instance

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityPolicySetEvent_allowedAudiencesFieldIsForkLocal pins the durable name of the list
// in the stored event: it carries the fork-local suffix, so the history is never read by code
// that knows the list under a plain name with other rules. An empty list is stored, not
// omitted, so a set that clears the list is replayed as a clear.
func TestSecurityPolicySetEvent_allowedAudiencesFieldIsForkLocal(t *testing.T) {
	event, err := NewSecurityPolicySetEvent(context.Background(), &NewAggregate("instance").Aggregate, []SecurityPolicyChanges{
		ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences([]string{"123"}),
	})
	require.NoError(t, err)
	payload, err := json.Marshal(event.Payload())
	require.NoError(t, err)
	assert.JSONEq(t, `{"client_id_metadata_document_allowed_audiences_ixcans_fork": ["123"]}`, string(payload))

	event, err = NewSecurityPolicySetEvent(context.Background(), &NewAggregate("instance").Aggregate, []SecurityPolicyChanges{
		ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences(nil),
	})
	require.NoError(t, err)
	payload, err = json.Marshal(event.Payload())
	require.NoError(t, err)
	assert.JSONEq(t, `{"client_id_metadata_document_allowed_audiences_ixcans_fork": []}`, string(payload))
	assert.Empty(t, event.UniqueConstraints(), "the audience list takes no unique constraints")
}

// TestSecurityPolicyClientIDMetadataDocumentAllowedAudienceEvents pins the durable event types
// and payloads of single additions and removals.
func TestSecurityPolicyClientIDMetadataDocumentAllowedAudienceEvents(t *testing.T) {
	agg := &NewAggregate("instance").Aggregate

	added := NewSecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent(context.Background(), agg, "123")
	assert.Equal(t, "instance.policy.security.client_id_metadata_document.allowed_audience_ixcans_fork.added", string(added.Type()))
	payload, err := json.Marshal(added.Payload())
	require.NoError(t, err)
	assert.JSONEq(t, `{"project_id": "123"}`, string(payload))
	assert.Empty(t, added.UniqueConstraints())

	removed := NewSecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent(context.Background(), agg, "123")
	assert.Equal(t, "instance.policy.security.client_id_metadata_document.allowed_audience_ixcans_fork.removed", string(removed.Type()))
	payload, err = json.Marshal(removed.Payload())
	require.NoError(t, err)
	assert.JSONEq(t, `{"project_id": "123"}`, string(payload))
	assert.Empty(t, removed.UniqueConstraints())

	for _, eventType := range []string{string(added.Type()), string(removed.Type())} {
		assert.True(t, strings.Contains(eventType, "_ixcans_fork"), eventType)
	}
}
