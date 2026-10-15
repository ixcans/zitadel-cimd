package instance

import (
	"context"

	"github.com/zitadel/zitadel/internal/eventstore"
)

// ixcans/zitadel-cimd fork: the allowed audiences of client ID metadata document clients are
// fork-local. Like the CIMD fields of SecurityPolicySetEvent, the event types below carry an
// "_ixcans_fork" marker, so stock code that might one day ship its own events under the plain
// names never reduces this durable history under different rules: it has no mapper for these
// types and ignores them.
const (
	securityPolicyClientIDMetadataDocumentAllowedAudiencePrefix           = securityPolicyPrefix + "client_id_metadata_document.allowed_audience_ixcans_fork."
	SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEventType   = instanceEventTypePrefix + securityPolicyClientIDMetadataDocumentAllowedAudiencePrefix + "added"
	SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEventType = instanceEventTypePrefix + securityPolicyClientIDMetadataDocumentAllowedAudiencePrefix + "removed"
)

// ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences replaces the IDs of the projects
// that clients resolved from a Client ID Metadata Document may request as an audience. An empty
// list is stored as such, so a set without the list clears it.
func ChangeSecurityPolicyClientIDMetadataDocumentAllowedAudiences(projectIDs []string) func(event *SecurityPolicySetEvent) {
	return func(e *SecurityPolicySetEvent) {
		if len(projectIDs) == 0 {
			projectIDs = []string{}
		}
		e.ClientIDMetadataDocumentAllowedAudiences = &projectIDs
	}
}

// SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent adds a project that clients
// resolved from a Client ID Metadata Document may request as an audience. It is a separate event
// rather than a set of the whole list, so concurrent additions do not overwrite each other.
type SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent struct {
	eventstore.BaseEvent `json:"-"`

	ProjectID string `json:"project_id"`
}

func (e *SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent) SetBaseEvent(event *eventstore.BaseEvent) {
	e.BaseEvent = *event
}

func NewSecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	projectID string,
) *SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent {
	return &SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEventType,
		),
		ProjectID: projectID,
	}
}

func (e *SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent) Payload() interface{} {
	return e
}

func (e *SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

// SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent removes a project that
// clients resolved from a Client ID Metadata Document may request as an audience.
type SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent struct {
	eventstore.BaseEvent `json:"-"`

	ProjectID string `json:"project_id"`
}

func (e *SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent) SetBaseEvent(event *eventstore.BaseEvent) {
	e.BaseEvent = *event
}

func NewSecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	projectID string,
) *SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent {
	return &SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEventType,
		),
		ProjectID: projectID,
	}
}

func (e *SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent) Payload() interface{} {
	return e
}

func (e *SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}
