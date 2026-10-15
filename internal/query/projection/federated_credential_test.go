package projection

import (
	"database/sql"
	"testing"
	"time"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/repository/org"
	"github.com/zitadel/zitadel/internal/repository/user"
	"github.com/zitadel/zitadel/internal/zerrors"
)

func TestFederatedCredentialProjection_reduces(t *testing.T) {
	type args struct {
		event func(t *testing.T) eventstore.Event
	}
	tests := []struct {
		name   string
		args   args
		reduce func(event eventstore.Event) (*handler.Statement, error)
		want   wantReduce
	}{
		{
			name: "reduceAdded",
			args: args{
				event: getEvent(
					testEvent(
						user.MachineFederatedCredentialAddedEventType,
						user.AggregateType,
						[]byte(`{
							"credentialId": "cred-id",
							"issuer": "https://issuer.example.com",
							"keySource": 1,
							"algorithms": ["ES256", "RS256"],
							"audience": "aud",
							"subjectRule": {"claim": "sub", "pattern": "repo:acme/.+"},
							"claimConditions": [{"claim": "env", "value": "prod"}],
							"maxTokenAge": 60000000000,
							"maxTokenLifetime": 120000000000
						}`),
					), eventstore.GenericEventMapper[user.MachineFederatedCredentialAddedEvent]),
			},
			reduce: (&federatedCredentialProjection{}).reduceAdded,
			want: wantReduce{
				aggregateType: user.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "INSERT INTO projections.federated_credentials_ixcans_fork (id, creation_date, change_date, sequence, resource_owner, instance_id, user_id, issuer, key_source, pinned_keys, algorithms, audience, subject_claim, subject_exact, subject_pattern, claim_conditions, max_token_age, max_token_lifetime, disabled) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
							expectedArgs: []interface{}{
								"cred-id",
								anyArg{},
								anyArg{},
								uint64(15),
								"ro-id",
								"instance-id",
								"agg-id",
								"https://issuer.example.com",
								domain.FederatedCredentialKeySourceIssuerMetadata,
								sql.NullString{},
								database.TextArray[string]{"ES256", "RS256"},
								"aud",
								"sub",
								sql.NullString{},
								sql.NullString{String: "repo:acme/.+", Valid: true},
								[]byte(`[{"claim":"env","value":"prod"}]`),
								time.Minute,
								2 * time.Minute,
								false,
							},
						},
					},
				},
			},
		},
		{
			name: "reduceAdded disabled with pinned keys and no conditions",
			args: args{
				event: getEvent(
					testEvent(
						user.MachineFederatedCredentialAddedEventType,
						user.AggregateType,
						[]byte(`{
							"credentialId": "cred-id",
							"issuer": "https://issuer.example.com",
							"keySource": 2,
							"pinnedKeys": "{\"keys\":[]}",
							"algorithms": ["EdDSA"],
							"audience": "aud",
							"subjectRule": {"claim": "sub", "exact": "workload"},
							"maxTokenAge": 60000000000,
							"maxTokenLifetime": 120000000000,
							"disabled": true
						}`),
					), eventstore.GenericEventMapper[user.MachineFederatedCredentialAddedEvent]),
			},
			reduce: (&federatedCredentialProjection{}).reduceAdded,
			want: wantReduce{
				aggregateType: user.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "INSERT INTO projections.federated_credentials_ixcans_fork (id, creation_date, change_date, sequence, resource_owner, instance_id, user_id, issuer, key_source, pinned_keys, algorithms, audience, subject_claim, subject_exact, subject_pattern, claim_conditions, max_token_age, max_token_lifetime, disabled) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
							expectedArgs: []interface{}{
								"cred-id",
								anyArg{},
								anyArg{},
								uint64(15),
								"ro-id",
								"instance-id",
								"agg-id",
								"https://issuer.example.com",
								domain.FederatedCredentialKeySourcePinnedKeys,
								sql.NullString{String: `{"keys":[]}`, Valid: true},
								database.TextArray[string]{"EdDSA"},
								"aud",
								"sub",
								sql.NullString{String: "workload", Valid: true},
								sql.NullString{},
								[]byte(`[]`),
								time.Minute,
								2 * time.Minute,
								true,
							},
						},
					},
				},
			},
		},
		{
			name: "reduceChanged disabled",
			args: args{
				event: getEvent(
					testEvent(
						user.MachineFederatedCredentialChangedEventType,
						user.AggregateType,
						[]byte(`{"credentialId": "cred-id", "disabled": true}`),
					), eventstore.GenericEventMapper[user.MachineFederatedCredentialChangedEvent]),
			},
			reduce: (&federatedCredentialProjection{}).reduceChanged,
			want: wantReduce{
				aggregateType: user.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "UPDATE projections.federated_credentials_ixcans_fork SET (change_date, sequence, disabled) = ($1, $2, $3) WHERE (instance_id = $4) AND (id = $5)",
							expectedArgs: []interface{}{
								anyArg{},
								uint64(15),
								true,
								"instance-id",
								"cred-id",
							},
						},
					},
				},
			},
		},
		{
			name: "reduceChanged enabled",
			args: args{
				event: getEvent(
					testEvent(
						user.MachineFederatedCredentialChangedEventType,
						user.AggregateType,
						[]byte(`{"credentialId": "cred-id", "disabled": false}`),
					), eventstore.GenericEventMapper[user.MachineFederatedCredentialChangedEvent]),
			},
			reduce: (&federatedCredentialProjection{}).reduceChanged,
			want: wantReduce{
				aggregateType: user.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "UPDATE projections.federated_credentials_ixcans_fork SET (change_date, sequence, disabled) = ($1, $2, $3) WHERE (instance_id = $4) AND (id = $5)",
							expectedArgs: []interface{}{
								anyArg{},
								uint64(15),
								false,
								"instance-id",
								"cred-id",
							},
						},
					},
				},
			},
		},
		{
			name: "reduceChanged every field",
			args: args{
				event: getEvent(
					testEvent(
						user.MachineFederatedCredentialChangedEventType,
						user.AggregateType,
						[]byte(`{
							"credentialId": "cred-id",
							"issuer": "https://other.example.com",
							"keySource": 1,
							"pinnedKeys": "",
							"algorithms": ["RS256"],
							"audience": "aud2",
							"subjectRule": {"claim": "oid", "exact": "123"},
							"claimConditions": [],
							"maxTokenAge": 30000000000,
							"maxTokenLifetime": 60000000000,
							"disabled": false
						}`),
					), eventstore.GenericEventMapper[user.MachineFederatedCredentialChangedEvent]),
			},
			reduce: (&federatedCredentialProjection{}).reduceChanged,
			want: wantReduce{
				aggregateType: user.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "UPDATE projections.federated_credentials_ixcans_fork SET (change_date, sequence, issuer, key_source, pinned_keys, algorithms, audience, subject_claim, subject_exact, subject_pattern, claim_conditions, max_token_age, max_token_lifetime, disabled) = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) WHERE (instance_id = $15) AND (id = $16)",
							expectedArgs: []interface{}{
								anyArg{},
								uint64(15),
								"https://other.example.com",
								domain.FederatedCredentialKeySourceIssuerMetadata,
								sql.NullString{},
								database.TextArray[string]{"RS256"},
								"aud2",
								"oid",
								sql.NullString{String: "123", Valid: true},
								sql.NullString{},
								[]byte(`[]`),
								30 * time.Second,
								time.Minute,
								false,
								"instance-id",
								"cred-id",
							},
						},
					},
				},
			},
		},
		{
			name: "reduceRemoved",
			args: args{
				event: getEvent(
					testEvent(
						user.MachineFederatedCredentialRemovedEventType,
						user.AggregateType,
						[]byte(`{"credentialId": "cred-id"}`),
					), eventstore.GenericEventMapper[user.MachineFederatedCredentialRemovedEvent]),
			},
			reduce: (&federatedCredentialProjection{}).reduceRemoved,
			want: wantReduce{
				aggregateType: user.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "DELETE FROM projections.federated_credentials_ixcans_fork WHERE (instance_id = $1) AND (id = $2)",
							expectedArgs: []interface{}{
								"instance-id",
								"cred-id",
							},
						},
					},
				},
			},
		},
		{
			name: "reduceUserRemoved",
			args: args{
				event: getEvent(
					testEvent(
						user.UserRemovedType,
						user.AggregateType,
						nil,
					), user.UserRemovedEventMapper),
			},
			reduce: (&federatedCredentialProjection{}).reduceUserRemoved,
			want: wantReduce{
				aggregateType: user.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "DELETE FROM projections.federated_credentials_ixcans_fork WHERE (instance_id = $1) AND (user_id = $2)",
							expectedArgs: []interface{}{
								"instance-id",
								"agg-id",
							},
						},
					},
				},
			},
		},
		{
			name: "reduceOwnerRemoved",
			args: args{
				event: getEvent(
					testEvent(
						org.OrgRemovedEventType,
						org.AggregateType,
						nil,
					), org.OrgRemovedEventMapper),
			},
			reduce: (&federatedCredentialProjection{}).reduceOwnerRemoved,
			want: wantReduce{
				aggregateType: org.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "DELETE FROM projections.federated_credentials_ixcans_fork WHERE (instance_id = $1) AND (resource_owner = $2)",
							expectedArgs: []interface{}{
								"instance-id",
								"agg-id",
							},
						},
					},
				},
			},
		},
		{
			name: "instance reduceInstanceRemoved",
			args: args{
				event: getEvent(
					testEvent(
						instance.InstanceRemovedEventType,
						instance.AggregateType,
						nil,
					), instance.InstanceRemovedEventMapper),
			},
			reduce: reduceInstanceRemovedHelper(FederatedCredentialInstanceIDCol),
			want: wantReduce{
				aggregateType: instance.AggregateType,
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: "DELETE FROM projections.federated_credentials_ixcans_fork WHERE (instance_id = $1)",
							expectedArgs: []interface{}{
								"agg-id",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := baseEvent(t)
			got, err := tt.reduce(event)
			if !zerrors.IsErrorInvalidArgument(err) {
				t.Errorf("no wrong event mapping: %v, got: %v", err, got)
			}

			event = tt.args.event(t)
			got, err = tt.reduce(event)
			assertReduce(t, got, err, FederatedCredentialTable, tt.want)
		})
	}
}
