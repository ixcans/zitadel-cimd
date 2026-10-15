package projection

import (
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/zerrors"
)

func (p *securityPolicyProjection) reduceClientIDMetadataDocumentAllowedAudienceAdded(event eventstore.Event) (*handler.Statement, error) {
	e, ok := event.(*instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent)
	if !ok {
		return nil, zerrors.ThrowInvalidArgumentf(nil, "HANDL-vT3eA", "reduce.wrong.event.type %s", instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEventType)
	}
	// The same upsert and array change as an allowed URL, applied to the audiences column.
	return p.reduceClientIDMetadataDocumentAllowedURLs(e, newArrayAppendUniqueCol(SecurityPolicyColumnClientIDMetadataDocumentAllowedAudiences, e.ProjectID)), nil
}

func (p *securityPolicyProjection) reduceClientIDMetadataDocumentAllowedAudienceRemoved(event eventstore.Event) (*handler.Statement, error) {
	e, ok := event.(*instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent)
	if !ok {
		return nil, zerrors.ThrowInvalidArgumentf(nil, "HANDL-b9QnR", "reduce.wrong.event.type %s", instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEventType)
	}
	return p.reduceClientIDMetadataDocumentAllowedURLs(e, handler.NewArrayRemoveCol(SecurityPolicyColumnClientIDMetadataDocumentAllowedAudiences, e.ProjectID)), nil
}
