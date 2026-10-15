package query

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"time"

	sq "github.com/Masterminds/squirrel"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query/projection"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

var (
	federatedCredentialTable = table{
		name:          projection.FederatedCredentialTable,
		instanceIDCol: projection.FederatedCredentialInstanceIDCol,
	}
	FederatedCredentialColumnID = Column{
		name:  projection.FederatedCredentialIDCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnCreationDate = Column{
		name:  projection.FederatedCredentialCreationDateCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnChangeDate = Column{
		name:  projection.FederatedCredentialChangeDateCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnSequence = Column{
		name:  projection.FederatedCredentialSequenceCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnResourceOwner = Column{
		name:  projection.FederatedCredentialResourceOwnerCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnInstanceID = Column{
		name:  projection.FederatedCredentialInstanceIDCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnUserID = Column{
		name:  projection.FederatedCredentialUserIDCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnIssuer = Column{
		name:  projection.FederatedCredentialIssuerCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnKeySource = Column{
		name:  projection.FederatedCredentialKeySourceCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnPinnedKeys = Column{
		name:  projection.FederatedCredentialPinnedKeysCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnAlgorithms = Column{
		name:  projection.FederatedCredentialAlgorithmsCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnAudience = Column{
		name:  projection.FederatedCredentialAudienceCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnSubjectClaim = Column{
		name:  projection.FederatedCredentialSubjectClaimCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnSubjectExact = Column{
		name:  projection.FederatedCredentialSubjectExactCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnSubjectPattern = Column{
		name:  projection.FederatedCredentialSubjectPatternCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnClaimConditions = Column{
		name:  projection.FederatedCredentialClaimConditionsCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnMaxTokenAge = Column{
		name:  projection.FederatedCredentialMaxTokenAgeCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnMaxTokenLifetime = Column{
		name:  projection.FederatedCredentialMaxTokenLifetimeCol,
		table: federatedCredentialTable,
	}
	FederatedCredentialColumnDisabled = Column{
		name:  projection.FederatedCredentialDisabledCol,
		table: federatedCredentialTable,
	}
)

// FederatedCredential is a federated credential of a machine user as the read model holds it.
type FederatedCredential struct {
	ID            string
	UserID        string
	CreationDate  time.Time
	ChangeDate    time.Time
	Sequence      uint64
	ResourceOwner string

	domain.FederatedCredential
}

type FederatedCredentials struct {
	SearchResponse
	FederatedCredentials []*FederatedCredential
}

type FederatedCredentialSearchQueries struct {
	SearchRequest
	Queries []SearchQuery
}

func (q *FederatedCredentialSearchQueries) toQuery(query sq.SelectBuilder) sq.SelectBuilder {
	query = q.SearchRequest.toQuery(query)
	for _, q := range q.Queries {
		query = q.toQuery(query)
	}
	return query
}

func NewFederatedCredentialUserIDSearchQuery(userID string) (SearchQuery, error) {
	return NewTextQuery(FederatedCredentialColumnUserID, userID, TextEquals)
}

func NewFederatedCredentialIDSearchQuery(id string) (SearchQuery, error) {
	return NewTextQuery(FederatedCredentialColumnID, id, TextEquals)
}

// NewFederatedCredentialIssuerSearchQuery finds the credentials whose issuer is exactly issuer.
func NewFederatedCredentialIssuerSearchQuery(issuer string) (SearchQuery, error) {
	return NewTextQuery(FederatedCredentialColumnIssuer, issuer, TextEquals)
}

// NewFederatedCredentialEnabledSearchQuery leaves out disabled credentials.
func NewFederatedCredentialEnabledSearchQuery() (SearchQuery, error) {
	return NewBoolQuery(FederatedCredentialColumnDisabled, false)
}

// SearchFederatedCredentials returns the federated credentials of the instance that match the
// queries, disabled ones included unless a query leaves them out. With a permission check, only
// credentials of users the caller holds user.federated_credential.read on are returned; without one
// (the token endpoint's lookup by issuer) nothing is filtered.
func (q *Queries) SearchFederatedCredentials(ctx context.Context, queries *FederatedCredentialSearchQueries, permissionCheck domain.PermissionCheck) (credentials *FederatedCredentials, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	query, scan := prepareFederatedCredentialsQuery()
	stmt, args, err := queries.toQuery(query).
		Where(sq.Eq{FederatedCredentialColumnInstanceID.identifier(): authz.GetInstance(ctx).InstanceID()}).
		ToSql()
	if err != nil {
		return nil, zerrors.ThrowInvalidArgument(err, "QUERY-Fc1sql", "Errors.Query.InvalidRequest")
	}
	err = q.client.QueryContext(ctx, func(rows *sql.Rows) error {
		credentials, err = scan(rows)
		return err
	}, stmt, args...)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "QUERY-Fc2sql", "Errors.Internal")
	}
	if permissionCheck != nil {
		federatedCredentialsCheckPermission(ctx, credentials, permissionCheck)
	}
	credentials.State, err = q.latestState(ctx, federatedCredentialTable)
	return credentials, err
}

// federatedCredentialsCheckPermission drops the credentials of users the caller may not read the
// federated credentials of, and does not count them. Unlike a user's own profile, a user cannot
// read its own federated credentials without the permission.
func federatedCredentialsCheckPermission(ctx context.Context, credentials *FederatedCredentials, permissionCheck domain.PermissionCheck) {
	before := len(credentials.FederatedCredentials)
	credentials.FederatedCredentials = slices.DeleteFunc(credentials.FederatedCredentials,
		func(credential *FederatedCredential) bool {
			return permissionCheck(ctx, domain.PermissionUserFederatedCredentialRead, credential.ResourceOwner, credential.UserID) != nil
		},
	)
	removed := uint64(before - len(credentials.FederatedCredentials))
	if len(credentials.FederatedCredentials) == 0 || removed > credentials.Count {
		credentials.Count = 0
		return
	}
	credentials.Count -= removed
}

func prepareFederatedCredentialsQuery() (sq.SelectBuilder, func(*sql.Rows) (*FederatedCredentials, error)) {
	return sq.Select(
			FederatedCredentialColumnID.identifier(),
			FederatedCredentialColumnUserID.identifier(),
			FederatedCredentialColumnCreationDate.identifier(),
			FederatedCredentialColumnChangeDate.identifier(),
			FederatedCredentialColumnSequence.identifier(),
			FederatedCredentialColumnResourceOwner.identifier(),
			FederatedCredentialColumnIssuer.identifier(),
			FederatedCredentialColumnKeySource.identifier(),
			FederatedCredentialColumnPinnedKeys.identifier(),
			FederatedCredentialColumnAlgorithms.identifier(),
			FederatedCredentialColumnAudience.identifier(),
			FederatedCredentialColumnSubjectClaim.identifier(),
			FederatedCredentialColumnSubjectExact.identifier(),
			FederatedCredentialColumnSubjectPattern.identifier(),
			FederatedCredentialColumnClaimConditions.identifier(),
			FederatedCredentialColumnMaxTokenAge.identifier(),
			FederatedCredentialColumnMaxTokenLifetime.identifier(),
			FederatedCredentialColumnDisabled.identifier(),
			countColumn.identifier(),
		).From(federatedCredentialTable.identifier()).
			PlaceholderFormat(sq.Dollar),
		func(rows *sql.Rows) (*FederatedCredentials, error) {
			credentials := make([]*FederatedCredential, 0)
			var count uint64
			for rows.Next() {
				credential := new(FederatedCredential)
				var (
					pinnedKeys, subjectExact, subjectPattern sql.NullString
					algorithms                               database.TextArray[string]
					conditions                               []byte
				)
				err := rows.Scan(
					&credential.ID,
					&credential.UserID,
					&credential.CreationDate,
					&credential.ChangeDate,
					&credential.Sequence,
					&credential.ResourceOwner,
					&credential.Issuer,
					&credential.KeySource,
					&pinnedKeys,
					&algorithms,
					&credential.Audience,
					&credential.SubjectRule.Claim,
					&subjectExact,
					&subjectPattern,
					&conditions,
					&credential.MaxTokenAge,
					&credential.MaxTokenLifetime,
					&credential.Disabled,
					&count,
				)
				if err != nil {
					return nil, err
				}
				credential.PinnedKeys = pinnedKeys.String
				credential.Algorithms = algorithms
				credential.SubjectRule.Exact = subjectExact.String
				credential.SubjectRule.Pattern = subjectPattern.String
				if len(conditions) > 0 {
					if err := json.Unmarshal(conditions, &credential.ClaimConditions); err != nil {
						return nil, zerrors.ThrowInternal(err, "QUERY-Fc1con", "Errors.Internal")
					}
				}
				if len(credential.ClaimConditions) == 0 {
					credential.ClaimConditions = nil
				}
				credentials = append(credentials, credential)
			}
			if err := rows.Close(); err != nil {
				return nil, zerrors.ThrowInternal(err, "QUERY-Fc1row", "Errors.Query.CloseRows")
			}
			return &FederatedCredentials{
				FederatedCredentials: credentials,
				SearchResponse: SearchResponse{
					Count: count,
				},
			}, nil
		}
}
