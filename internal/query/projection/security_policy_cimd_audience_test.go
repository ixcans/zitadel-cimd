package projection

import (
	"testing"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/zerrors"
)

const securityPolicyUpsertWithAllowedAudiences = "INSERT INTO projections.security_policies3 (creation_date, change_date, instance_id, sequence, client_id_metadata_document_allowed_audiences) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (instance_id) DO UPDATE SET (creation_date, change_date, sequence, client_id_metadata_document_allowed_audiences) = (projections.security_policies3.creation_date, EXCLUDED.change_date, EXCLUDED.sequence, EXCLUDED.client_id_metadata_document_allowed_audiences)"

const securityPolicyUpsertWithoutChanges = "INSERT INTO projections.security_policies3 (creation_date, change_date, instance_id, sequence) VALUES ($1, $2, $3, $4) ON CONFLICT (instance_id) DO UPDATE SET (creation_date, change_date, sequence) = (projections.security_policies3.creation_date, EXCLUDED.change_date, EXCLUDED.sequence)"

func TestSecurityPolicyProjection_reducesClientIDMetadataDocumentAllowedAudiences(t *testing.T) {
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
			name:   "reduceSecurityPolicySet, list replaced",
			reduce: (&securityPolicyProjection{}).reduceSecurityPolicySet,
			args: args{
				event: getEvent(
					testEvent(
						instance.SecurityPolicySetEventType,
						instance.AggregateType,
						[]byte(`{"client_id_metadata_document_allowed_audiences_ixcans_fork": ["123", "456"]}`),
					), instance.SecurityPolicySetEventMapper),
			},
			want: wantReduce{
				aggregateType: eventstore.AggregateType("instance"),
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: securityPolicyUpsertWithAllowedAudiences,
							expectedArgs: []interface{}{
								anyArg{},
								anyArg{},
								"instance-id",
								uint64(15),
								&[]string{"123", "456"},
							},
						},
					},
				},
			},
		},
		{
			// A set that omits the list stores an empty list, so the column is cleared.
			name:   "reduceSecurityPolicySet, list cleared",
			reduce: (&securityPolicyProjection{}).reduceSecurityPolicySet,
			args: args{
				event: getEvent(
					testEvent(
						instance.SecurityPolicySetEventType,
						instance.AggregateType,
						[]byte(`{"client_id_metadata_document_allowed_audiences_ixcans_fork": []}`),
					), instance.SecurityPolicySetEventMapper),
			},
			want: wantReduce{
				aggregateType: eventstore.AggregateType("instance"),
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: securityPolicyUpsertWithAllowedAudiences,
							expectedArgs: []interface{}{
								anyArg{},
								anyArg{},
								"instance-id",
								uint64(15),
								&[]string{},
							},
						},
					},
				},
			},
		},
		{
			// The durable field name is fork-local: a payload under a plain name, as another
			// implementation might write it, does not change the list.
			name:   "reduceSecurityPolicySet, plain field name ignored",
			reduce: (&securityPolicyProjection{}).reduceSecurityPolicySet,
			args: args{
				event: getEvent(
					testEvent(
						instance.SecurityPolicySetEventType,
						instance.AggregateType,
						[]byte(`{"client_id_metadata_document_allowed_audiences": ["123"]}`),
					), instance.SecurityPolicySetEventMapper),
			},
			want: wantReduce{
				aggregateType: eventstore.AggregateType("instance"),
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: securityPolicyUpsertWithoutChanges,
							expectedArgs: []interface{}{
								anyArg{},
								anyArg{},
								"instance-id",
								uint64(15),
							},
						},
					},
				},
			},
		},
		{
			name:   "reduceClientIDMetadataDocumentAllowedAudienceAdded",
			reduce: (&securityPolicyProjection{}).reduceClientIDMetadataDocumentAllowedAudienceAdded,
			args: args{
				event: getEvent(
					testEvent(
						instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEventType,
						instance.AggregateType,
						[]byte(`{"project_id": "123"}`),
					), eventstore.GenericEventMapper[instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceAddedEvent]),
			},
			want: wantReduce{
				aggregateType: eventstore.AggregateType("instance"),
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: securityPolicyUpsertWithoutChanges,
							expectedArgs: []interface{}{
								anyArg{},
								anyArg{},
								"instance-id",
								uint64(15),
							},
						},
						{
							expectedStmt: "UPDATE projections.security_policies3 SET client_id_metadata_document_allowed_audiences = array_append(array_remove(COALESCE(client_id_metadata_document_allowed_audiences, '{}'), $1), $1) WHERE (instance_id = $2)",
							expectedArgs: []interface{}{
								"123",
								"instance-id",
							},
						},
					},
				},
			},
		},
		{
			name:   "reduceClientIDMetadataDocumentAllowedAudienceRemoved",
			reduce: (&securityPolicyProjection{}).reduceClientIDMetadataDocumentAllowedAudienceRemoved,
			args: args{
				event: getEvent(
					testEvent(
						instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEventType,
						instance.AggregateType,
						[]byte(`{"project_id": "123"}`),
					), eventstore.GenericEventMapper[instance.SecurityPolicyClientIDMetadataDocumentAllowedAudienceRemovedEvent]),
			},
			want: wantReduce{
				aggregateType: eventstore.AggregateType("instance"),
				sequence:      15,
				executer: &testExecuter{
					executions: []execution{
						{
							expectedStmt: securityPolicyUpsertWithoutChanges,
							expectedArgs: []interface{}{
								anyArg{},
								anyArg{},
								"instance-id",
								uint64(15),
							},
						},
						{
							expectedStmt: "UPDATE projections.security_policies3 SET client_id_metadata_document_allowed_audiences = array_remove(client_id_metadata_document_allowed_audiences, $1) WHERE (instance_id = $2)",
							expectedArgs: []interface{}{
								"123",
								"instance-id",
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
			if ok := zerrors.IsErrorInvalidArgument(err); !ok {
				t.Errorf("no wrong event mapping: %v, got: %v", err, got)
			}

			event = tt.args.event(t)
			got, err = tt.reduce(event)
			assertReduce(t, got, err, SecurityPolicyProjectionTable, tt.want)
		})
	}
}
