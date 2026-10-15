package projection

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	old_handler "github.com/zitadel/zitadel/internal/eventstore/handler"
	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/repository/org"
	"github.com/zitadel/zitadel/internal/repository/user"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// The federated credentials of machine users (fork-only). The table name carries the fork's
// suffix, like the event types, so that it cannot collide with a table of a later upstream version.
const (
	FederatedCredentialTable               = "projections.federated_credentials_ixcans_fork"
	FederatedCredentialIDCol               = "id"
	FederatedCredentialCreationDateCol     = "creation_date"
	FederatedCredentialChangeDateCol       = "change_date"
	FederatedCredentialSequenceCol         = "sequence"
	FederatedCredentialResourceOwnerCol    = "resource_owner"
	FederatedCredentialInstanceIDCol       = "instance_id"
	FederatedCredentialUserIDCol           = "user_id"
	FederatedCredentialIssuerCol           = "issuer"
	FederatedCredentialKeySourceCol        = "key_source"
	FederatedCredentialPinnedKeysCol       = "pinned_keys"
	FederatedCredentialAlgorithmsCol       = "algorithms"
	FederatedCredentialAudienceCol         = "audience"
	FederatedCredentialSubjectClaimCol     = "subject_claim"
	FederatedCredentialSubjectExactCol     = "subject_exact"
	FederatedCredentialSubjectPatternCol   = "subject_pattern"
	FederatedCredentialClaimConditionsCol  = "claim_conditions"
	FederatedCredentialMaxTokenAgeCol      = "max_token_age"
	FederatedCredentialMaxTokenLifetimeCol = "max_token_lifetime"
	FederatedCredentialDisabledCol         = "disabled"
)

type federatedCredentialProjection struct{}

func newFederatedCredentialProjection(ctx context.Context, config handler.Config) *handler.Handler {
	return handler.NewHandler(ctx, &config, new(federatedCredentialProjection))
}

func (*federatedCredentialProjection) Name() string {
	return FederatedCredentialTable
}

func (*federatedCredentialProjection) Init() *old_handler.Check {
	return handler.NewTableCheck(
		handler.NewTable([]*handler.InitColumn{
			handler.NewColumn(FederatedCredentialIDCol, handler.ColumnTypeText),
			handler.NewColumn(FederatedCredentialCreationDateCol, handler.ColumnTypeTimestamp),
			handler.NewColumn(FederatedCredentialChangeDateCol, handler.ColumnTypeTimestamp),
			handler.NewColumn(FederatedCredentialSequenceCol, handler.ColumnTypeInt64),
			handler.NewColumn(FederatedCredentialResourceOwnerCol, handler.ColumnTypeText),
			handler.NewColumn(FederatedCredentialInstanceIDCol, handler.ColumnTypeText),
			handler.NewColumn(FederatedCredentialUserIDCol, handler.ColumnTypeText),
			handler.NewColumn(FederatedCredentialIssuerCol, handler.ColumnTypeText),
			handler.NewColumn(FederatedCredentialKeySourceCol, handler.ColumnTypeEnum),
			handler.NewColumn(FederatedCredentialPinnedKeysCol, handler.ColumnTypeText, handler.Nullable()),
			handler.NewColumn(FederatedCredentialAlgorithmsCol, handler.ColumnTypeTextArray),
			handler.NewColumn(FederatedCredentialAudienceCol, handler.ColumnTypeText),
			handler.NewColumn(FederatedCredentialSubjectClaimCol, handler.ColumnTypeText),
			handler.NewColumn(FederatedCredentialSubjectExactCol, handler.ColumnTypeText, handler.Nullable()),
			handler.NewColumn(FederatedCredentialSubjectPatternCol, handler.ColumnTypeText, handler.Nullable()),
			handler.NewColumn(FederatedCredentialClaimConditionsCol, handler.ColumnTypeJSONB),
			handler.NewColumn(FederatedCredentialMaxTokenAgeCol, handler.ColumnTypeInt64),
			handler.NewColumn(FederatedCredentialMaxTokenLifetimeCol, handler.ColumnTypeInt64),
			handler.NewColumn(FederatedCredentialDisabledCol, handler.ColumnTypeBool, handler.Default(false)),
		},
			handler.NewPrimaryKey(FederatedCredentialInstanceIDCol, FederatedCredentialIDCol),
			handler.WithIndex(handler.NewIndex("user_id", []string{FederatedCredentialUserIDCol})),
			handler.WithIndex(handler.NewIndex("issuer", []string{FederatedCredentialIssuerCol})),
			handler.WithIndex(handler.NewIndex("resource_owner", []string{FederatedCredentialResourceOwnerCol})),
		),
	)
}

func (p *federatedCredentialProjection) Reducers() []handler.AggregateReducer {
	return []handler.AggregateReducer{
		{
			Aggregate: user.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  user.MachineFederatedCredentialAddedEventType,
					Reduce: p.reduceAdded,
				},
				{
					Event:  user.MachineFederatedCredentialChangedEventType,
					Reduce: p.reduceChanged,
				},
				{
					Event:  user.MachineFederatedCredentialRemovedEventType,
					Reduce: p.reduceRemoved,
				},
				{
					Event:  user.UserRemovedType,
					Reduce: p.reduceUserRemoved,
				},
			},
		},
		{
			Aggregate: org.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  org.OrgRemovedEventType,
					Reduce: p.reduceOwnerRemoved,
				},
			},
		},
		{
			Aggregate: instance.AggregateType,
			EventReducers: []handler.EventReducer{
				{
					Event:  instance.InstanceRemovedEventType,
					Reduce: reduceInstanceRemovedHelper(FederatedCredentialInstanceIDCol),
				},
			},
		},
	}
}

func (p *federatedCredentialProjection) reduceAdded(event eventstore.Event) (*handler.Statement, error) {
	e, err := assertEvent[*user.MachineFederatedCredentialAddedEvent](event)
	if err != nil {
		return nil, err
	}
	conditions, err := federatedCredentialConditionsColumn(e.ClaimConditions)
	if err != nil {
		return nil, err
	}
	return handler.NewCreateStatement(
		e,
		[]handler.Column{
			handler.NewCol(FederatedCredentialIDCol, e.CredentialID),
			handler.NewCol(FederatedCredentialCreationDateCol, e.CreationDate()),
			handler.NewCol(FederatedCredentialChangeDateCol, e.CreationDate()),
			handler.NewCol(FederatedCredentialSequenceCol, e.Sequence()),
			handler.NewCol(FederatedCredentialResourceOwnerCol, e.Aggregate().ResourceOwner),
			handler.NewCol(FederatedCredentialInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCol(FederatedCredentialUserIDCol, e.Aggregate().ID),
			handler.NewCol(FederatedCredentialIssuerCol, e.Issuer),
			handler.NewCol(FederatedCredentialKeySourceCol, e.KeySource),
			handler.NewCol(FederatedCredentialPinnedKeysCol, federatedCredentialNullString(e.PinnedKeys)),
			handler.NewCol(FederatedCredentialAlgorithmsCol, database.TextArray[string](e.Algorithms)),
			handler.NewCol(FederatedCredentialAudienceCol, e.Audience),
			handler.NewCol(FederatedCredentialSubjectClaimCol, e.SubjectRule.Claim),
			handler.NewCol(FederatedCredentialSubjectExactCol, federatedCredentialNullString(e.SubjectRule.Exact)),
			handler.NewCol(FederatedCredentialSubjectPatternCol, federatedCredentialNullString(e.SubjectRule.Pattern)),
			handler.NewCol(FederatedCredentialClaimConditionsCol, conditions),
			handler.NewCol(FederatedCredentialMaxTokenAgeCol, e.MaxTokenAge),
			handler.NewCol(FederatedCredentialMaxTokenLifetimeCol, e.MaxTokenLifetime),
			handler.NewCol(FederatedCredentialDisabledCol, e.Disabled),
		},
	), nil
}

func (p *federatedCredentialProjection) reduceChanged(event eventstore.Event) (*handler.Statement, error) {
	e, err := assertEvent[*user.MachineFederatedCredentialChangedEvent](event)
	if err != nil {
		return nil, err
	}
	columns := []handler.Column{
		handler.NewCol(FederatedCredentialChangeDateCol, e.CreationDate()),
		handler.NewCol(FederatedCredentialSequenceCol, e.Sequence()),
	}
	if e.Issuer != nil {
		columns = append(columns, handler.NewCol(FederatedCredentialIssuerCol, *e.Issuer))
	}
	if e.KeySource != nil {
		columns = append(columns, handler.NewCol(FederatedCredentialKeySourceCol, *e.KeySource))
	}
	if e.PinnedKeys != nil {
		columns = append(columns, handler.NewCol(FederatedCredentialPinnedKeysCol, federatedCredentialNullString(*e.PinnedKeys)))
	}
	if e.Algorithms != nil {
		columns = append(columns, handler.NewCol(FederatedCredentialAlgorithmsCol, database.TextArray[string](*e.Algorithms)))
	}
	if e.Audience != nil {
		columns = append(columns, handler.NewCol(FederatedCredentialAudienceCol, *e.Audience))
	}
	if e.SubjectRule != nil {
		columns = append(columns,
			handler.NewCol(FederatedCredentialSubjectClaimCol, e.SubjectRule.Claim),
			handler.NewCol(FederatedCredentialSubjectExactCol, federatedCredentialNullString(e.SubjectRule.Exact)),
			handler.NewCol(FederatedCredentialSubjectPatternCol, federatedCredentialNullString(e.SubjectRule.Pattern)),
		)
	}
	if e.ClaimConditions != nil {
		conditions, err := federatedCredentialConditionsColumn(*e.ClaimConditions)
		if err != nil {
			return nil, err
		}
		columns = append(columns, handler.NewCol(FederatedCredentialClaimConditionsCol, conditions))
	}
	if e.MaxTokenAge != nil {
		columns = append(columns, handler.NewCol(FederatedCredentialMaxTokenAgeCol, *e.MaxTokenAge))
	}
	if e.MaxTokenLifetime != nil {
		columns = append(columns, handler.NewCol(FederatedCredentialMaxTokenLifetimeCol, *e.MaxTokenLifetime))
	}
	if e.Disabled != nil {
		columns = append(columns, handler.NewCol(FederatedCredentialDisabledCol, *e.Disabled))
	}
	return handler.NewUpdateStatement(
		e,
		columns,
		[]handler.Condition{
			handler.NewCond(FederatedCredentialInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCond(FederatedCredentialIDCol, e.CredentialID),
		},
	), nil
}

func (p *federatedCredentialProjection) reduceRemoved(event eventstore.Event) (*handler.Statement, error) {
	e, err := assertEvent[*user.MachineFederatedCredentialRemovedEvent](event)
	if err != nil {
		return nil, err
	}
	return handler.NewDeleteStatement(
		e,
		[]handler.Condition{
			handler.NewCond(FederatedCredentialInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCond(FederatedCredentialIDCol, e.CredentialID),
		},
	), nil
}

func (p *federatedCredentialProjection) reduceUserRemoved(event eventstore.Event) (*handler.Statement, error) {
	e, err := assertEvent[*user.UserRemovedEvent](event)
	if err != nil {
		return nil, err
	}
	return handler.NewDeleteStatement(
		e,
		[]handler.Condition{
			handler.NewCond(FederatedCredentialInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCond(FederatedCredentialUserIDCol, e.Aggregate().ID),
		},
	), nil
}

func (p *federatedCredentialProjection) reduceOwnerRemoved(event eventstore.Event) (*handler.Statement, error) {
	e, ok := event.(*org.OrgRemovedEvent)
	if !ok {
		return nil, zerrors.ThrowInvalidArgumentf(nil, "PROJE-Fc1own", "reduce.wrong.event.type %s", org.OrgRemovedEventType)
	}
	return handler.NewDeleteStatement(
		e,
		[]handler.Condition{
			handler.NewCond(FederatedCredentialInstanceIDCol, e.Aggregate().InstanceID),
			handler.NewCond(FederatedCredentialResourceOwnerCol, e.Aggregate().ID),
		},
	), nil
}

// federatedCredentialConditionsColumn stores the claim conditions as a JSON array, [] when there
// are none.
func federatedCredentialConditionsColumn(conditions []domain.FederatedCredentialClaimCondition) ([]byte, error) {
	if conditions == nil {
		conditions = []domain.FederatedCredentialClaimCondition{}
	}
	data, err := json.Marshal(conditions)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "PROJE-Fc1con", "Errors.Internal")
	}
	return data, nil
}

func federatedCredentialNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
