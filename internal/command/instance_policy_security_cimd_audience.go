package command

import (
	"context"
	"slices"
	"strings"
	"unicode"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// maxClientIDMetadataDocumentAllowedAudienceLength is the longest project ID the list accepts,
// the same bound the APIs put on resource IDs.
const maxClientIDMetadataDocumentAllowedAudienceLength = 200

// AddClientIDMetadataDocumentAllowedAudience adds a project that clients resolved from a Client
// ID Metadata Document may request as an audience. The project must not be allowed already, and
// it must not be the ZITADEL project.
func (c *Commands) AddClientIDMetadataDocumentAllowedAudience(ctx context.Context, projectID string) (*domain.ObjectDetails, error) {
	if err := validateClientIDMetadataDocumentAllowedAudience(ctx, projectID); err != nil {
		return nil, err
	}
	writeModel := NewInstanceSecurityPolicyWriteModel(ctx)
	if err := c.eventstore.FilterToQueryReducer(ctx, writeModel); err != nil {
		return nil, err
	}
	if slices.Contains(writeModel.ClientIDMetadataDocumentAllowedAudiences, projectID) {
		return nil, zerrors.ThrowAlreadyExists(nil, "COMMA-q8Wd3", "Errors.Instance.SecurityPolicy.ClientIDMetadataDocumentAllowedAudience.AlreadyExists")
	}
	err := c.pushAppendAndReduce(ctx, writeModel, instance.NewSecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent(ctx, InstanceAggregateFromWriteModel(&writeModel.WriteModel), projectID))
	if err != nil {
		return nil, err
	}
	return writeModelToObjectDetails(&writeModel.WriteModel), nil
}

// RemoveClientIDMetadataDocumentAllowedAudience removes a project that clients resolved from a
// Client ID Metadata Document may request as an audience. Removing a project that is not allowed
// is not an error and returns no details.
func (c *Commands) RemoveClientIDMetadataDocumentAllowedAudience(ctx context.Context, projectID string) (*domain.ObjectDetails, error) {
	writeModel := NewInstanceSecurityPolicyWriteModel(ctx)
	if err := c.eventstore.FilterToQueryReducer(ctx, writeModel); err != nil {
		return nil, err
	}
	if !slices.Contains(writeModel.ClientIDMetadataDocumentAllowedAudiences, projectID) {
		return nil, nil
	}
	err := c.pushAppendAndReduce(ctx, writeModel, instance.NewSecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent(ctx, InstanceAggregateFromWriteModel(&writeModel.WriteModel), projectID))
	if err != nil {
		return nil, err
	}
	return writeModelToObjectDetails(&writeModel.WriteModel), nil
}

// reduceClientIDMetadataDocumentAllowedAudience applies an added or removed audience to the write
// model. An addition of a project that is already allowed changes nothing, so the list stays
// free of duplicates even if two additions of the same project were pushed concurrently.
func (wm *InstanceSecurityPolicyWriteModel) reduceClientIDMetadataDocumentAllowedAudience(event eventstore.Event) {
	switch e := event.(type) {
	case *instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent:
		if !slices.Contains(wm.ClientIDMetadataDocumentAllowedAudiences, e.ProjectID) {
			wm.ClientIDMetadataDocumentAllowedAudiences = append(wm.ClientIDMetadataDocumentAllowedAudiences, e.ProjectID)
		}
	case *instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent:
		wm.ClientIDMetadataDocumentAllowedAudiences = slices.DeleteFunc(wm.ClientIDMetadataDocumentAllowedAudiences, func(projectID string) bool {
			return projectID == e.ProjectID
		})
	}
}

// validateClientIDMetadataDocumentAllowedAudiences validates every entry of a list that replaces
// the allowed audiences, and refuses a list that names a project twice.
func validateClientIDMetadataDocumentAllowedAudiences(ctx context.Context, projectIDs []string) error {
	for i, projectID := range projectIDs {
		if err := validateClientIDMetadataDocumentAllowedAudience(ctx, projectID); err != nil {
			return err
		}
		if slices.Contains(projectIDs[:i], projectID) {
			return zerrors.ThrowInvalidArgument(nil, "COMMA-Zr2pT", "Errors.Instance.SecurityPolicy.ClientIDMetadataDocumentAllowedAudience.AlreadyExists")
		}
	}
	return nil
}

// validateClientIDMetadataDocumentAllowedAudience requires projectID to be an ID that an audience
// scope (urn:zitadel:iam:org:project:id:{projectID}:aud) names unambiguously, and refuses the
// ZITADEL project, by its reserved name or by the instance's project ID: the instance's own API
// is never an audience of a client resolved from a Client ID Metadata Document.
func validateClientIDMetadataDocumentAllowedAudience(ctx context.Context, projectID string) error {
	if projectID == "" ||
		len(projectID) > maxClientIDMetadataDocumentAllowedAudienceLength ||
		strings.ContainsFunc(projectID, func(r rune) bool {
			return r == ':' || unicode.IsSpace(r) || !unicode.IsPrint(r)
		}) {
		return zerrors.ThrowInvalidArgument(nil, "COMMA-m5Kc9", "Errors.Instance.SecurityPolicy.ClientIDMetadataDocumentAllowedAudience.Invalid")
	}
	if projectID == domain.ProjectIDScopeZITADEL || projectID == authz.GetInstance(ctx).ProjectID() {
		return zerrors.ThrowInvalidArgument(nil, "COMMA-Hn6vB", "Errors.Instance.SecurityPolicy.ClientIDMetadataDocumentAllowedAudience.Reserved")
	}
	return nil
}
