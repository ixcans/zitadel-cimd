package setup

import (
	"context"
	_ "embed"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/eventstore"
)

var (
	//go:embed 82.sql
	addSecurityPolicyClientIDMetadataDocumentAllowedAudiences string
)

// SecurityPolicies3AddClientIDMetadataDocumentAllowedAudiences adds the column of the projects
// that clients resolved from a Client ID Metadata Document may request as an audience.
type SecurityPolicies3AddClientIDMetadataDocumentAllowedAudiences struct {
	dbClient *database.DB
}

func (mig *SecurityPolicies3AddClientIDMetadataDocumentAllowedAudiences) Execute(ctx context.Context, _ eventstore.Event) error {
	_, err := mig.dbClient.ExecContext(ctx, addSecurityPolicyClientIDMetadataDocumentAllowedAudiences)
	return err
}

func (mig *SecurityPolicies3AddClientIDMetadataDocumentAllowedAudiences) String() string {
	return "82_security_policies3_add_client_id_metadata_document_allowed_audiences"
}
