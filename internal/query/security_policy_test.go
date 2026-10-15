package query

import (
	"database/sql/driver"
	"regexp"
	"testing"

	"github.com/zitadel/zitadel/internal/database"
)

var (
	prepareSecurityPolicyStmt = `SELECT projections.security_policies3.instance_id,` +
		` projections.security_policies3.creation_date,` +
		` projections.security_policies3.change_date,` +
		` projections.security_policies3.instance_id,` +
		` projections.security_policies3.sequence,` +
		` projections.security_policies3.enable_iframe_embedding,` +
		` projections.security_policies3.origins,` +
		` projections.security_policies3.enable_impersonation,` +
		` projections.security_policies3.enable_dynamic_client_registration,` +
		` projections.security_policies3.allow_unauthenticated_dynamic_client_registration,` +
		` projections.security_policies3.enable_client_id_metadata_document,` +
		` projections.security_policies3.client_id_metadata_document_allowed_urls,` +
		` projections.security_policies3.client_id_metadata_document_allow_any_url,` +
		` projections.security_policies3.client_id_metadata_document_allowed_audiences` +
		` FROM projections.security_policies3`

	prepareSecurityPolicyCols = []string{
		"instance_id",
		"creation_date",
		"change_date",
		"instance_id",
		"sequence",
		"enable_iframe_embedding",
		"origins",
		"enable_impersonation",
		"enable_dynamic_client_registration",
		"allow_unauthenticated_dynamic_client_registration",
		"enable_client_id_metadata_document",
		"client_id_metadata_document_allowed_urls",
		"client_id_metadata_document_allow_any_url",
		"client_id_metadata_document_allowed_audiences",
	}
)

// Test_SecurityPolicyPrepares pins that reading the security settings returns the client ID
// metadata document settings, the allowed audiences included.
func Test_SecurityPolicyPrepares(t *testing.T) {
	type want struct {
		sqlExpectations sqlExpectation
		err             checkErr
	}
	tests := []struct {
		name    string
		prepare interface{}
		want    want
		object  interface{}
	}{
		{
			name:    "prepareSecurityPolicyQuery found",
			prepare: prepareSecurityPolicyQuery,
			want: want{
				sqlExpectations: mockQuery(
					regexp.QuoteMeta(prepareSecurityPolicyStmt),
					prepareSecurityPolicyCols,
					[]driver.Value{
						"instance-id",
						testNow,
						testNow,
						"instance-id",
						uint64(20211109),
						true,
						database.TextArray[string]{"https://origin.example.com"},
						true,
						true,
						false,
						true,
						database.TextArray[string]{"https://clients.example.com/"},
						false,
						database.TextArray[string]{"123", "456"},
					},
				),
			},
			object: &SecurityPolicy{
				AggregateID:   "instance-id",
				CreationDate:  testNow,
				ChangeDate:    testNow,
				ResourceOwner: "instance-id",
				Sequence:      20211109,

				EnableIframeEmbedding: true,
				AllowedOrigins:        database.TextArray[string]{"https://origin.example.com"},
				EnableImpersonation:   true,

				EnableDynamicClientRegistration: true,

				EnableClientIDMetadataDocument:           true,
				ClientIDMetadataDocumentAllowedURLs:      database.TextArray[string]{"https://clients.example.com/"},
				ClientIDMetadataDocumentAllowedAudiences: database.TextArray[string]{"123", "456"},
			},
		},
		{
			name:    "prepareSecurityPolicyQuery never set",
			prepare: prepareSecurityPolicyQuery,
			want: want{
				sqlExpectations: mockQuery(
					regexp.QuoteMeta(prepareSecurityPolicyStmt),
					prepareSecurityPolicyCols,
					nil,
				),
			},
			object: &SecurityPolicy{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertPrepare(t, tt.prepare, tt.object, tt.want.sqlExpectations, tt.want.err)
		})
	}
}
