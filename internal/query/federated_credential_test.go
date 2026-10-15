package query

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/zerrors"
)

var (
	prepareFederatedCredentialsStmt = `SELECT projections.federated_credentials_ixcans_fork.id,` +
		` projections.federated_credentials_ixcans_fork.user_id,` +
		` projections.federated_credentials_ixcans_fork.creation_date,` +
		` projections.federated_credentials_ixcans_fork.change_date,` +
		` projections.federated_credentials_ixcans_fork.sequence,` +
		` projections.federated_credentials_ixcans_fork.resource_owner,` +
		` projections.federated_credentials_ixcans_fork.issuer,` +
		` projections.federated_credentials_ixcans_fork.key_source,` +
		` projections.federated_credentials_ixcans_fork.pinned_keys,` +
		` projections.federated_credentials_ixcans_fork.algorithms,` +
		` projections.federated_credentials_ixcans_fork.audience,` +
		` projections.federated_credentials_ixcans_fork.subject_claim,` +
		` projections.federated_credentials_ixcans_fork.subject_exact,` +
		` projections.federated_credentials_ixcans_fork.subject_pattern,` +
		` projections.federated_credentials_ixcans_fork.claim_conditions,` +
		` projections.federated_credentials_ixcans_fork.max_token_age,` +
		` projections.federated_credentials_ixcans_fork.max_token_lifetime,` +
		` projections.federated_credentials_ixcans_fork.disabled,` +
		` COUNT(*) OVER ()` +
		` FROM projections.federated_credentials_ixcans_fork`
	prepareFederatedCredentialsCols = []string{
		"id",
		"user_id",
		"creation_date",
		"change_date",
		"sequence",
		"resource_owner",
		"issuer",
		"key_source",
		"pinned_keys",
		"algorithms",
		"audience",
		"subject_claim",
		"subject_exact",
		"subject_pattern",
		"claim_conditions",
		"max_token_age",
		"max_token_lifetime",
		"disabled",
		"count",
	}
)

func Test_FederatedCredentialPrepares(t *testing.T) {
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
			name:    "prepareFederatedCredentialsQuery no result",
			prepare: prepareFederatedCredentialsQuery,
			want: want{
				sqlExpectations: mockQueries(
					regexp.QuoteMeta(prepareFederatedCredentialsStmt),
					nil,
					nil,
				),
			},
			object: &FederatedCredentials{FederatedCredentials: []*FederatedCredential{}},
		},
		{
			name:    "prepareFederatedCredentialsQuery results",
			prepare: prepareFederatedCredentialsQuery,
			want: want{
				sqlExpectations: mockQueries(
					regexp.QuoteMeta(prepareFederatedCredentialsStmt),
					prepareFederatedCredentialsCols,
					[][]driver.Value{
						{
							"cred1",
							"user1",
							testNow,
							testNow,
							uint64(20211109),
							"ro",
							"https://issuer.example.com",
							1,
							nil,
							database.TextArray[string]{"ES256", "RS256"},
							"aud",
							"sub",
							nil,
							"repo:acme/.+",
							[]byte(`[{"claim":"env","value":"prod"}]`),
							int64(time.Minute),
							int64(2 * time.Minute),
							false,
						},
						{
							"cred2",
							"user1",
							testNow,
							testNow,
							uint64(20211110),
							"ro",
							"https://kubernetes.default.svc",
							2,
							`{"keys":[]}`,
							database.TextArray[string]{"EdDSA"},
							"aud",
							"sub",
							"system:serviceaccount:ci:deployer",
							nil,
							[]byte(`[]`),
							int64(time.Hour),
							int64(time.Hour),
							true,
						},
					},
				),
			},
			object: &FederatedCredentials{
				SearchResponse: SearchResponse{Count: 2},
				FederatedCredentials: []*FederatedCredential{
					{
						ID:            "cred1",
						UserID:        "user1",
						CreationDate:  testNow,
						ChangeDate:    testNow,
						Sequence:      20211109,
						ResourceOwner: "ro",
						FederatedCredential: domain.FederatedCredential{
							Issuer:           "https://issuer.example.com",
							KeySource:        domain.FederatedCredentialKeySourceIssuerMetadata,
							Algorithms:       []string{"ES256", "RS256"},
							Audience:         "aud",
							SubjectRule:      domain.FederatedCredentialSubjectRule{Claim: "sub", Pattern: "repo:acme/.+"},
							ClaimConditions:  []domain.FederatedCredentialClaimCondition{{Claim: "env", Value: "prod"}},
							MaxTokenAge:      time.Minute,
							MaxTokenLifetime: 2 * time.Minute,
						},
					},
					{
						ID:            "cred2",
						UserID:        "user1",
						CreationDate:  testNow,
						ChangeDate:    testNow,
						Sequence:      20211110,
						ResourceOwner: "ro",
						FederatedCredential: domain.FederatedCredential{
							Issuer:           "https://kubernetes.default.svc",
							KeySource:        domain.FederatedCredentialKeySourcePinnedKeys,
							PinnedKeys:       `{"keys":[]}`,
							Algorithms:       []string{"EdDSA"},
							Audience:         "aud",
							SubjectRule:      domain.FederatedCredentialSubjectRule{Claim: "sub", Exact: "system:serviceaccount:ci:deployer"},
							MaxTokenAge:      time.Hour,
							MaxTokenLifetime: time.Hour,
							Disabled:         true,
						},
					},
				},
			},
		},
		{
			name:    "prepareFederatedCredentialsQuery sql err",
			prepare: prepareFederatedCredentialsQuery,
			want: want{
				sqlExpectations: mockQueryErr(
					regexp.QuoteMeta(prepareFederatedCredentialsStmt),
					sql.ErrConnDone,
				),
				err: func(err error) (error, bool) {
					if !errors.Is(err, sql.ErrConnDone) {
						return fmt.Errorf("err should be sql.ErrConnDone got: %w", err), false
					}
					return nil, true
				},
			},
			object: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertPrepare(t, tt.prepare, tt.object, tt.want.sqlExpectations, tt.want.err)
		})
	}
}

func Test_federatedCredentialsCheckPermission(t *testing.T) {
	credentials := func() *FederatedCredentials {
		return &FederatedCredentials{FederatedCredentials: []*FederatedCredential{
			{ID: "cred1", UserID: "user1", ResourceOwner: "org1"},
			{ID: "cred2", UserID: "user2", ResourceOwner: "org2"},
		}}
	}
	tests := []struct {
		name            string
		ctx             context.Context
		permissionCheck domain.PermissionCheck
		want            []string
	}{
		{
			name: "read permission on every user",
			ctx:  context.Background(),
			permissionCheck: func(_ context.Context, permission, _, _ string) error {
				if permission == domain.PermissionUserFederatedCredentialRead {
					return nil
				}
				return zerrors.ThrowPermissionDenied(nil, "TEST", "denied")
			},
			want: []string{"cred1", "cred2"},
		},
		{
			name: "read permission in one organization",
			ctx:  context.Background(),
			permissionCheck: func(_ context.Context, permission, resourceOwner, _ string) error {
				if permission == domain.PermissionUserFederatedCredentialRead && resourceOwner == "org2" {
					return nil
				}
				return zerrors.ThrowPermissionDenied(nil, "TEST", "denied")
			},
			want: []string{"cred2"},
		},
		{
			name: "user read permission only",
			ctx:  context.Background(),
			permissionCheck: func(_ context.Context, permission, _, _ string) error {
				if permission == domain.PermissionUserRead {
					return nil
				}
				return zerrors.ThrowPermissionDenied(nil, "TEST", "denied")
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := credentials()
			federatedCredentialsCheckPermission(tt.ctx, got, tt.permissionCheck)
			ids := make([]string, 0, len(got.FederatedCredentials))
			for _, credential := range got.FederatedCredentials {
				ids = append(ids, credential.ID)
			}
			assert.Equal(t, tt.want, ids)
		})
	}
}
