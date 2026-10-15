package command

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/id"
	id_mock "github.com/zitadel/zitadel/internal/id/mock"
	"github.com/zitadel/zitadel/internal/repository/user"
	"github.com/zitadel/zitadel/internal/zerrors"
)

func federatedCredentialTestContext() context.Context {
	return authz.NewMockContext("instance1", "org1", "admin1")
}

func federatedCredentialTestAggregate() *eventstore.Aggregate {
	return &user.NewAggregate("user1", "org1").Aggregate
}

func federatedCredentialTestConfig() *domain.FederatedCredential {
	return &domain.FederatedCredential{
		Issuer:     "https://token.ci.example.com",
		KeySource:  domain.FederatedCredentialKeySourceIssuerMetadata,
		Algorithms: []string{"RS256"},
		Audience:   "https://auth.example.com",
		SubjectRule: domain.FederatedCredentialSubjectRule{
			Claim:   "sub",
			Pattern: `repo:acme/deploy:ref:refs/heads/.+`,
		},
		ClaimConditions: []domain.FederatedCredentialClaimCondition{
			{Claim: "repository_owner_id", Value: "42"},
		},
		MaxTokenAge:      10 * time.Minute,
		MaxTokenLifetime: 5 * time.Minute,
	}
}

func machineAddedForFederatedCredential() eventstore.Event {
	return eventFromEventPusher(user.NewMachineAddedEvent(context.Background(),
		federatedCredentialTestAggregate(), "machine", "Machine", "", true, domain.OIDCTokenTypeJWT))
}

func humanAddedForFederatedCredential() eventstore.Event {
	return eventFromEventPusher(user.NewHumanAddedEvent(context.Background(),
		federatedCredentialTestAggregate(), "human", "First", "Last", "", "First Last",
		language.English, domain.GenderUnspecified, "human@example.com", true))
}

func federatedCredentialAdded(credentialID string, credential *domain.FederatedCredential) eventstore.Event {
	return eventFromEventPusher(user.NewMachineFederatedCredentialAddedEvent(context.Background(),
		federatedCredentialTestAggregate(), credentialID, credential))
}

// permissionCheckAllowing allows exactly one permission and denies every other.
func permissionCheckAllowing(allowed string) domain.PermissionCheck {
	return func(_ context.Context, permission, _, _ string) error {
		if permission == allowed {
			return nil
		}
		return zerrors.ThrowPermissionDenied(nil, "AUTHZ-HKJD33", "Errors.PermissionDenied")
	}
}

func TestCommands_AddMachineFederatedCredential(t *testing.T) {
	type fields struct {
		eventstore      func(*testing.T) *eventstore.Eventstore
		idGenerator     id.Generator
		checkPermission domain.PermissionCheck
	}
	type args struct {
		ctx        context.Context
		userID     string
		credential *domain.FederatedCredential
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantID  string
		wantErr func(error) bool
	}{
		{
			name:    "user ID missing",
			fields:  fields{eventstore: expectEventstore()},
			args:    args{ctx: federatedCredentialTestContext(), credential: federatedCredentialTestConfig()},
			wantErr: zerrors.IsErrorInvalidArgument,
		},
		{
			name:   "invalid credential is refused before anything is read",
			fields: fields{eventstore: expectEventstore()},
			args: args{ctx: federatedCredentialTestContext(), userID: "user1", credential: func() *domain.FederatedCredential {
				c := federatedCredentialTestConfig()
				c.Issuer = "http://token.ci.example.com"
				return c
			}()},
			wantErr: zerrors.IsErrorInvalidArgument,
		},
		{
			name: "user not found",
			fields: fields{
				eventstore:      expectEventstore(expectFilter()),
				idGenerator:     id_mock.NewIDGeneratorExpectIDs(t, "cred1"),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args:    args{ctx: federatedCredentialTestContext(), userID: "user1", credential: federatedCredentialTestConfig()},
			wantErr: zerrors.IsNotFound,
		},
		{
			name: "removed user",
			fields: fields{
				eventstore: expectEventstore(expectFilter(
					machineAddedForFederatedCredential(),
					eventFromEventPusher(user.NewUserRemovedEvent(context.Background(), federatedCredentialTestAggregate(), "machine", nil, true)),
				)),
				idGenerator:     id_mock.NewIDGeneratorExpectIDs(t, "cred1"),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args:    args{ctx: federatedCredentialTestContext(), userID: "user1", credential: federatedCredentialTestConfig()},
			wantErr: zerrors.IsNotFound,
		},
		{
			name: "human user is refused",
			fields: fields{
				eventstore:      expectEventstore(expectFilter(humanAddedForFederatedCredential())),
				idGenerator:     id_mock.NewIDGeneratorExpectIDs(t, "cred1"),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args:    args{ctx: federatedCredentialTestContext(), userID: "user1", credential: federatedCredentialTestConfig()},
			wantErr: zerrors.IsPreconditionFailed,
		},
		{
			name: "caller without permission",
			fields: fields{
				eventstore:      expectEventstore(expectFilter(machineAddedForFederatedCredential())),
				idGenerator:     id_mock.NewIDGeneratorExpectIDs(t, "cred1"),
				checkPermission: newMockPermissionCheckNotAllowed(),
			},
			args:    args{ctx: federatedCredentialTestContext(), userID: "user1", credential: federatedCredentialTestConfig()},
			wantErr: zerrors.IsPermissionDenied,
		},
		{
			name: "caller allowed to manage the user's keys only",
			fields: fields{
				eventstore:      expectEventstore(expectFilter(machineAddedForFederatedCredential())),
				idGenerator:     id_mock.NewIDGeneratorExpectIDs(t, "cred1"),
				checkPermission: permissionCheckAllowing(domain.PermissionUserWrite),
			},
			args:    args{ctx: federatedCredentialTestContext(), userID: "user1", credential: federatedCredentialTestConfig()},
			wantErr: zerrors.IsPermissionDenied,
		},
		{
			name: "machine user cannot add one to itself",
			fields: fields{
				eventstore:      expectEventstore(expectFilter(machineAddedForFederatedCredential())),
				idGenerator:     id_mock.NewIDGeneratorExpectIDs(t, "cred1"),
				checkPermission: newMockPermissionCheckNotAllowed(),
			},
			args:    args{ctx: authz.NewMockContext("instance1", "org1", "user1"), userID: "user1", credential: federatedCredentialTestConfig()},
			wantErr: zerrors.IsPermissionDenied,
		},
		{
			name: "added",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(machineAddedForFederatedCredential()),
					expectPush(user.NewMachineFederatedCredentialAddedEvent(federatedCredentialTestContext(),
						federatedCredentialTestAggregate(), "cred1", federatedCredentialTestConfig())),
				),
				idGenerator:     id_mock.NewIDGeneratorExpectIDs(t, "cred1"),
				checkPermission: permissionCheckAllowing(domain.PermissionUserFederatedCredentialWrite),
			},
			args:   args{ctx: federatedCredentialTestContext(), userID: "user1", credential: federatedCredentialTestConfig()},
			wantID: "cred1",
		},
		{
			name: "added disabled",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(machineAddedForFederatedCredential()),
					expectPush(user.NewMachineFederatedCredentialAddedEvent(federatedCredentialTestContext(),
						federatedCredentialTestAggregate(), "cred1", func() *domain.FederatedCredential {
							c := federatedCredentialTestConfig()
							c.Disabled = true
							return c
						}())),
				),
				idGenerator:     id_mock.NewIDGeneratorExpectIDs(t, "cred1"),
				checkPermission: permissionCheckAllowing(domain.PermissionUserFederatedCredentialWrite),
			},
			args: args{ctx: federatedCredentialTestContext(), userID: "user1", credential: func() *domain.FederatedCredential {
				c := federatedCredentialTestConfig()
				c.Disabled = true
				return c
			}()},
			wantID: "cred1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Commands{
				eventstore:      tt.fields.eventstore(t),
				idGenerator:     tt.fields.idGenerator,
				checkPermission: tt.fields.checkPermission,
			}
			gotID, details, err := c.AddMachineFederatedCredential(tt.args.ctx, tt.args.userID, "", tt.args.credential)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.True(t, tt.wantErr(err), "unexpected error: %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, gotID)
			assert.Equal(t, "org1", details.ResourceOwner)
		})
	}
}

func TestCommands_ChangeMachineFederatedCredential(t *testing.T) {
	disabled, enabled := true, false
	otherAudience := "other-audience"
	pinnedKeySource := domain.FederatedCredentialKeySourcePinnedKeys
	pinnedKeys := `{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`
	disabledConfig := func() *domain.FederatedCredential {
		c := federatedCredentialTestConfig()
		c.Disabled = true
		return c
	}
	type fields struct {
		eventstore      func(*testing.T) *eventstore.Eventstore
		checkPermission domain.PermissionCheck
	}
	tests := []struct {
		name         string
		fields       fields
		credentialID string
		change       *ChangeMachineFederatedCredential
		wantErr      func(error) bool
	}{
		{
			name:         "credential ID missing",
			fields:       fields{eventstore: expectEventstore()},
			change:       &ChangeMachineFederatedCredential{Disabled: &disabled},
			wantErr:      zerrors.IsErrorInvalidArgument,
			credentialID: "",
		},
		{
			name: "credential not found",
			fields: fields{
				eventstore:      expectEventstore(expectFilter(machineAddedForFederatedCredential())),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			credentialID: "cred1",
			change:       &ChangeMachineFederatedCredential{Disabled: &disabled},
			wantErr:      zerrors.IsNotFound,
		},
		{
			name: "credential of another ID is not found",
			fields: fields{
				eventstore: expectEventstore(expectFilter(
					machineAddedForFederatedCredential(),
					federatedCredentialAdded("cred2", federatedCredentialTestConfig()),
				)),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			credentialID: "cred1",
			change:       &ChangeMachineFederatedCredential{Disabled: &disabled},
			wantErr:      zerrors.IsNotFound,
		},
		{
			name: "credential removed",
			fields: fields{
				eventstore: expectEventstore(expectFilter(
					machineAddedForFederatedCredential(),
					federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
					eventFromEventPusher(user.NewMachineFederatedCredentialRemovedEvent(context.Background(), federatedCredentialTestAggregate(), "cred1")),
				)),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			credentialID: "cred1",
			change:       &ChangeMachineFederatedCredential{Disabled: &disabled},
			wantErr:      zerrors.IsNotFound,
		},
		{
			name: "caller allowed to manage the user's keys only",
			fields: fields{
				eventstore: expectEventstore(expectFilter(
					machineAddedForFederatedCredential(),
					federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
				)),
				checkPermission: permissionCheckAllowing(domain.PermissionUserWrite),
			},
			credentialID: "cred1",
			change:       &ChangeMachineFederatedCredential{Disabled: &disabled},
			wantErr:      zerrors.IsPermissionDenied,
		},
		{
			name: "change that makes the credential invalid",
			fields: fields{
				eventstore: expectEventstore(expectFilter(
					machineAddedForFederatedCredential(),
					federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
				)),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			credentialID: "cred1",
			change:       &ChangeMachineFederatedCredential{Algorithms: []string{"HS256"}},
			wantErr:      zerrors.IsErrorInvalidArgument,
		},
		{
			name: "pattern that would match every subject",
			fields: fields{
				eventstore: expectEventstore(expectFilter(
					machineAddedForFederatedCredential(),
					federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
				)),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			credentialID: "cred1",
			change:       &ChangeMachineFederatedCredential{SubjectRule: &domain.FederatedCredentialSubjectRule{Claim: "sub", Pattern: ".*"}},
			wantErr:      zerrors.IsErrorInvalidArgument,
		},
		{
			name: "disabled",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						machineAddedForFederatedCredential(),
						federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
					),
					expectPush(user.NewMachineFederatedCredentialChangedEvent(federatedCredentialTestContext(),
						federatedCredentialTestAggregate(), "cred1", federatedCredentialTestConfig(), disabledConfig())),
				),
				checkPermission: permissionCheckAllowing(domain.PermissionUserFederatedCredentialWrite),
			},
			credentialID: "cred1",
			change:       &ChangeMachineFederatedCredential{Disabled: &disabled},
		},
		{
			name: "enabled again",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						machineAddedForFederatedCredential(),
						federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
						eventFromEventPusher(user.NewMachineFederatedCredentialChangedEvent(context.Background(),
							federatedCredentialTestAggregate(), "cred1", federatedCredentialTestConfig(), disabledConfig())),
					),
					expectPush(user.NewMachineFederatedCredentialChangedEvent(federatedCredentialTestContext(),
						federatedCredentialTestAggregate(), "cred1", disabledConfig(), federatedCredentialTestConfig())),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			credentialID: "cred1",
			change:       &ChangeMachineFederatedCredential{Disabled: &enabled},
		},
		{
			name: "no change writes no event",
			fields: fields{
				eventstore: expectEventstore(expectFilter(
					machineAddedForFederatedCredential(),
					federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
				)),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			credentialID: "cred1",
			change:       &ChangeMachineFederatedCredential{Disabled: &enabled, Algorithms: []string{"RS256"}},
		},
		{
			name: "audience and key source changed",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						machineAddedForFederatedCredential(),
						federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
					),
					expectPush(user.NewMachineFederatedCredentialChangedEvent(federatedCredentialTestContext(),
						federatedCredentialTestAggregate(), "cred1", federatedCredentialTestConfig(), func() *domain.FederatedCredential {
							c := federatedCredentialTestConfig()
							c.Audience = otherAudience
							c.KeySource = domain.FederatedCredentialKeySourcePinnedKeys
							c.PinnedKeys = pinnedKeys
							c.Algorithms = []string{"ES256"}
							c.ClaimConditions = nil
							return c
						}())),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			credentialID: "cred1",
			change: &ChangeMachineFederatedCredential{
				Audience:        &otherAudience,
				KeySource:       &pinnedKeySource,
				PinnedKeys:      pinnedKeys,
				Algorithms:      []string{"ES256"},
				ClaimConditions: &[]domain.FederatedCredentialClaimCondition{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Commands{
				eventstore:      tt.fields.eventstore(t),
				checkPermission: tt.fields.checkPermission,
			}
			details, err := c.ChangeMachineFederatedCredential(federatedCredentialTestContext(), "user1", tt.credentialID, "", tt.change)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.True(t, tt.wantErr(err), "unexpected error: %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "org1", details.ResourceOwner)
		})
	}
}

func TestCommands_RemoveMachineFederatedCredential(t *testing.T) {
	type fields struct {
		eventstore      func(*testing.T) *eventstore.Eventstore
		checkPermission domain.PermissionCheck
	}
	tests := []struct {
		name    string
		fields  fields
		userID  string
		wantErr func(error) bool
	}{
		{
			name:    "user ID missing",
			fields:  fields{eventstore: expectEventstore()},
			wantErr: zerrors.IsErrorInvalidArgument,
		},
		{
			name: "credential not found",
			fields: fields{
				eventstore:      expectEventstore(expectFilter(machineAddedForFederatedCredential())),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			userID:  "user1",
			wantErr: zerrors.IsNotFound,
		},
		{
			name: "caller allowed to write but not to delete",
			fields: fields{
				eventstore: expectEventstore(expectFilter(
					machineAddedForFederatedCredential(),
					federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
				)),
				checkPermission: permissionCheckAllowing(domain.PermissionUserFederatedCredentialWrite),
			},
			userID:  "user1",
			wantErr: zerrors.IsPermissionDenied,
		},
		{
			name: "removed",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						machineAddedForFederatedCredential(),
						federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
					),
					expectPush(user.NewMachineFederatedCredentialRemovedEvent(federatedCredentialTestContext(),
						federatedCredentialTestAggregate(), "cred1")),
				),
				checkPermission: permissionCheckAllowing(domain.PermissionUserFederatedCredentialDelete),
			},
			userID: "user1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Commands{
				eventstore:      tt.fields.eventstore(t),
				checkPermission: tt.fields.checkPermission,
			}
			details, err := c.RemoveMachineFederatedCredential(federatedCredentialTestContext(), tt.userID, "cred1", "")
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.True(t, tt.wantErr(err), "unexpected error: %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "org1", details.ResourceOwner)
		})
	}
}

// The machine user's own keys are untouched by federated credentials: a key added before a
// credential is still found by the key write model, and the credential events are invisible to it.
func TestMachineFederatedCredential_keysUnchanged(t *testing.T) {
	es := expectEventstore(expectFilter(
		machineAddedForFederatedCredential(),
		eventFromEventPusher(user.NewMachineKeyAddedEvent(context.Background(), federatedCredentialTestAggregate(),
			"key1", domain.AuthNKeyTypeJSON, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), nil)),
		federatedCredentialAdded("cred1", federatedCredentialTestConfig()),
		eventFromEventPusher(user.NewMachineFederatedCredentialRemovedEvent(context.Background(), federatedCredentialTestAggregate(), "cred1")),
	))(t)
	wm := NewMachineKeyWriteModel("user1", "key1", "org1")
	require.NoError(t, es.FilterToQueryReducer(context.Background(), wm))
	assert.True(t, wm.Exists())
	assert.Equal(t, domain.AuthNKeyTypeJSON, wm.KeyType)
	assert.NotContains(t, wm.Query().GetQueries()[0].GetEventTypes(), user.MachineFederatedCredentialAddedEventType)
}
