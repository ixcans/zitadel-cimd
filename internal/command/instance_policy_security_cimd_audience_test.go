package command

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/zerrors"
)

var (
	errAllowedAudienceInvalid       = zerrors.ThrowInvalidArgument(nil, "COMMA-m5Kc9", "Errors.Instance.SecurityPolicy.ClientIDMetadataDocumentAllowedAudience.Invalid")
	errAllowedAudienceReserved      = zerrors.ThrowInvalidArgument(nil, "COMMA-Hn6vB", "Errors.Instance.SecurityPolicy.ClientIDMetadataDocumentAllowedAudience.Reserved")
	errAllowedAudienceAlreadyExists = zerrors.ThrowAlreadyExists(nil, "COMMA-q8Wd3", "Errors.Instance.SecurityPolicy.ClientIDMetadataDocumentAllowedAudience.AlreadyExists")
	errAllowedAudienceDuplicate     = zerrors.ThrowInvalidArgument(nil, "COMMA-Zr2pT", "Errors.Instance.SecurityPolicy.ClientIDMetadataDocumentAllowedAudience.AlreadyExists")
)

func allowedAudienceAddedEvent(projectID string) *instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent {
	return instance.NewSecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent(context.Background(),
		&instance.NewAggregate("instanceID").Aggregate, projectID)
}

func allowedAudienceRemovedEvent(projectID string) *instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent {
	return instance.NewSecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent(context.Background(),
		&instance.NewAggregate("instanceID").Aggregate, projectID)
}

// instanceContext is an instance whose own (ZITADEL) project has the ID "iam-project".
func instanceContext() context.Context {
	return authz.NewMockContext("instanceID", "", "", authz.WithMockProjectID("iam-project"))
}

func TestCommands_AddClientIDMetadataDocumentAllowedAudience(t *testing.T) {
	type want struct {
		details *domain.ObjectDetails
		err     error
	}
	tests := []struct {
		name       string
		eventstore func(*testing.T) *eventstore.Eventstore
		projectID  string
		want       want
	}{
		{
			name:       "empty project id, error",
			eventstore: expectEventstore(),
			projectID:  "",
			want:       want{err: errAllowedAudienceInvalid},
		},
		{
			name:       "project id with a colon, error",
			eventstore: expectEventstore(),
			projectID:  "123:aud",
			want:       want{err: errAllowedAudienceInvalid},
		},
		{
			name:       "project id with whitespace, error",
			eventstore: expectEventstore(),
			projectID:  "123 456",
			want:       want{err: errAllowedAudienceInvalid},
		},
		{
			name:       "project id too long, error",
			eventstore: expectEventstore(),
			projectID:  strings.Repeat("1", 201),
			want:       want{err: errAllowedAudienceInvalid},
		},
		{
			name:       "zitadel project by its reserved name, error",
			eventstore: expectEventstore(),
			projectID:  "zitadel",
			want:       want{err: errAllowedAudienceReserved},
		},
		{
			name:       "zitadel project by the instance's project id, error",
			eventstore: expectEventstore(),
			projectID:  "iam-project",
			want:       want{err: errAllowedAudienceReserved},
		},
		{
			name: "project already allowed by setting the policy, error",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(securityPolicySetEvent(t,
						instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences([]string{"123"}),
					)),
				),
			),
			projectID: "123",
			want:      want{err: errAllowedAudienceAlreadyExists},
		},
		{
			name: "project already added, error",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(allowedAudienceAddedEvent("123")),
				),
			),
			projectID: "123",
			want:      want{err: errAllowedAudienceAlreadyExists},
		},
		{
			name: "project added again after removal, ok",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(allowedAudienceAddedEvent("123")),
					eventFromEventPusher(allowedAudienceRemovedEvent("123")),
				),
				expectPush(allowedAudienceAddedEvent("123")),
			),
			projectID: "123",
			want:      want{details: &domain.ObjectDetails{ResourceOwner: "instanceID"}},
		},
		{
			name: "project added next to other projects, ok",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(securityPolicySetEvent(t,
						instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences([]string{"123"}),
					)),
				),
				expectPush(allowedAudienceAddedEvent("456")),
			),
			projectID: "456",
			want:      want{details: &domain.ObjectDetails{ResourceOwner: "instanceID"}},
		},
		{
			name: "project added while only urls are allowed, ok",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(securityPolicySetEvent(t,
						instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedURLs([]string{"https://app.example.com/client"}),
					)),
				),
				expectPush(allowedAudienceAddedEvent("123")),
			),
			projectID: "123",
			want:      want{details: &domain.ObjectDetails{ResourceOwner: "instanceID"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Commands{
				eventstore: tt.eventstore(t),
			}
			got, err := c.AddClientIDMetadataDocumentAllowedAudience(instanceContext(), tt.projectID)
			assert.ErrorIs(t, err, tt.want.err)
			assertObjectDetails(t, tt.want.details, got)
		})
	}
}

func TestCommands_RemoveClientIDMetadataDocumentAllowedAudience(t *testing.T) {
	tests := []struct {
		name        string
		eventstore  func(*testing.T) *eventstore.Eventstore
		projectID   string
		wantDetails *domain.ObjectDetails
	}{
		{
			name:       "project not allowed, no error and no event",
			eventstore: expectEventstore(expectFilter()),
			projectID:  "123",
		},
		{
			name: "project removed before, no error and no event",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(allowedAudienceAddedEvent("123")),
					eventFromEventPusher(allowedAudienceRemovedEvent("123")),
				),
			),
			projectID: "123",
		},
		{
			name: "project cleared by setting the policy, no error and no event",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(allowedAudienceAddedEvent("123")),
					eventFromEventPusher(securityPolicySetEvent(t,
						instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences(nil),
					)),
				),
			),
			projectID: "123",
		},
		{
			name: "project allowed by setting the policy, removed",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(securityPolicySetEvent(t,
						instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences([]string{"123", "456"}),
					)),
				),
				expectPush(allowedAudienceRemovedEvent("123")),
			),
			projectID:   "123",
			wantDetails: &domain.ObjectDetails{ResourceOwner: "instanceID"},
		},
		{
			name: "added project, removed",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(allowedAudienceAddedEvent("123")),
				),
				expectPush(allowedAudienceRemovedEvent("123")),
			),
			projectID:   "123",
			wantDetails: &domain.ObjectDetails{ResourceOwner: "instanceID"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Commands{
				eventstore: tt.eventstore(t),
			}
			got, err := c.RemoveClientIDMetadataDocumentAllowedAudience(instanceContext(), tt.projectID)
			assert.NoError(t, err)
			if tt.wantDetails == nil {
				assert.Nil(t, got)
				return
			}
			assertObjectDetails(t, tt.wantDetails, got)
		})
	}
}

func TestCommands_SetSecurityPolicy_clientIDMetadataDocumentAllowedAudiences(t *testing.T) {
	tests := []struct {
		name       string
		eventstore func(*testing.T) *eventstore.Eventstore
		policy     *SecurityPolicy
		wantErr    error
	}{
		{
			name:       "invalid project id, error",
			eventstore: expectEventstore(),
			policy:     &SecurityPolicy{ClientIDMetadataDocumentAllowedAudiences: []string{"123", "urn:zitadel:iam:org:project:id:456:aud"}},
			wantErr:    errAllowedAudienceInvalid,
		},
		{
			name:       "zitadel project by its reserved name, error",
			eventstore: expectEventstore(),
			policy:     &SecurityPolicy{ClientIDMetadataDocumentAllowedAudiences: []string{"123", "zitadel"}},
			wantErr:    errAllowedAudienceReserved,
		},
		{
			name:       "zitadel project by the instance's project id, error",
			eventstore: expectEventstore(),
			policy:     &SecurityPolicy{ClientIDMetadataDocumentAllowedAudiences: []string{"iam-project"}},
			wantErr:    errAllowedAudienceReserved,
		},
		{
			name:       "project named twice, error",
			eventstore: expectEventstore(),
			policy:     &SecurityPolicy{ClientIDMetadataDocumentAllowedAudiences: []string{"123", "456", "123"}},
			wantErr:    errAllowedAudienceDuplicate,
		},
		{
			name: "list set next to the other client id metadata document settings",
			eventstore: expectEventstore(
				expectFilter(),
				expectPush(securityPolicySetEvent(t,
					instance.ChangeSecurityPolicyEnableClientIDMetadataDocument(true),
					instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedURLs([]string{"https://clients.example.com/"}),
					instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences([]string{"123", "456"}),
				)),
			),
			policy: &SecurityPolicy{
				EnableClientIDMetadataDocument:           true,
				ClientIDMetadataDocumentAllowedURLs:      []string{"https://clients.example.com/"},
				ClientIDMetadataDocumentAllowedAudiences: []string{"123", "456"},
			},
		},
		{
			name: "set list replaces added projects",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(allowedAudienceAddedEvent("123")),
				),
				expectPush(securityPolicySetEvent(t,
					instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences([]string{"456"}),
				)),
			),
			policy: &SecurityPolicy{ClientIDMetadataDocumentAllowedAudiences: []string{"456"}},
		},
		{
			// The set call replaces every setting, so a call that omits the list clears it.
			name: "set without the list clears it",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(securityPolicySetEvent(t,
						instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences([]string{"123"}),
					)),
					eventFromEventPusher(allowedAudienceAddedEvent("456")),
				),
				expectPush(securityPolicySetEvent(t,
					instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences(nil),
				)),
			),
			policy: &SecurityPolicy{},
		},
		{
			name: "unchanged list, not part of the change",
			eventstore: expectEventstore(
				expectFilter(
					eventFromEventPusher(securityPolicySetEvent(t,
						instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences([]string{"123"}),
					)),
					eventFromEventPusher(allowedAudienceAddedEvent("456")),
				),
				expectPush(securityPolicySetEvent(t,
					instance.ChangeSecurityPolicyEnableClientIDMetadataDocument(true),
				)),
			),
			policy: &SecurityPolicy{
				EnableClientIDMetadataDocument:           true,
				ClientIDMetadataDocumentAllowedAudiences: []string{"123", "456"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Commands{
				eventstore: tt.eventstore(t),
			}
			_, err := c.SetSecurityPolicy(instanceContext(), tt.policy)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// TestCommands_SetLegacySecurityPolicy_keepsClientIDMetadataDocumentAllowedAudiences pins that
// the admin v1 and settings v2beta APIs, which cannot express the list, do not clear it.
func TestCommands_SetLegacySecurityPolicy_keepsClientIDMetadataDocumentAllowedAudiences(t *testing.T) {
	c := &Commands{
		eventstore: expectEventstore(
			expectFilter(
				eventFromEventPusher(securityPolicySetEvent(t,
					instance.ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences([]string{"123"}),
				)),
				eventFromEventPusher(allowedAudienceAddedEvent("456")),
			),
			expectPush(securityPolicySetEvent(t,
				instance.ChangeSecurityPolicyEnableImpersonation(true),
			)),
		)(t),
	}
	_, err := c.SetLegacySecurityPolicy(instanceContext(), &SecurityPolicy{
		EnableImpersonation: true,
	})
	assert.NoError(t, err)
}
