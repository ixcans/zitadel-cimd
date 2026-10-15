package command

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/crypto"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/id/mock"
	"github.com/zitadel/zitadel/internal/repository/oidcsession"
	"github.com/zitadel/zitadel/internal/repository/user"
	"github.com/zitadel/zitadel/internal/zerrors"
)

func testFederatedCredentialExchange() *domain.FederatedCredentialExchange {
	return &domain.FederatedCredentialExchange{
		CredentialID:  "cred1",
		UserID:        "machine1",
		ResourceOwner: "org1",
		Issuer:        "https://issuer.example.com",
		Subject:       "system:serviceaccount:ns:workload",
		SubjectClaim:  "sub",
		SubjectValue:  "system:serviceaccount:ns:workload",
		TokenID:       "jti1",
		AssertionKey:  "1700000600:0123456789abcdef",
	}
}

func testMachineAddedEvent() eventstore.Event {
	return eventFromEventPusher(user.NewMachineAddedEvent(context.Background(),
		&user.NewAggregate("machine1", "org1").Aggregate,
		"machine-username", "machine", "", false, domain.OIDCTokenTypeJWT,
	))
}

// federatedSessionPush is the push of a session issued by a federated credential exchange: the
// exchanged event (with its single-use constraint) comes first, then the session and its token.
func federatedSessionPush(accessTokenLifetime time.Duration) []eventstore.Command {
	return []eventstore.Command{
		user.NewMachineFederatedCredentialExchangedEvent(context.Background(),
			&user.NewAggregate("machine1", "org1").Aggregate, "V2_oidcSessionID", testFederatedCredentialExchange()),
		oidcsession.NewAddedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
			"machine1", "org1", "", "machine-username", []string{"project1"}, []string{"openid"},
			[]domain.UserAuthMethodType{domain.UserAuthMethodTypeFederatedCredential}, testNow, "", nil, nil,
		),
		oidcsession.NewAccessTokenAddedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
			"at_accessTokenID", []string{"openid"}, accessTokenLifetime, domain.TokenReasonJWTProfile, nil),
	}
}

func createFederatedSession(c *Commands, opts ...OIDCSessionOption) (*OIDCSession, error) {
	return c.CreateOIDCSession(authz.WithInstanceID(context.Background(), "instanceID"),
		"machine1",
		"org1",
		"machine-username",
		"",
		[]string{"openid"},
		[]string{"project1"},
		[]domain.UserAuthMethodType{domain.UserAuthMethodTypeFederatedCredential},
		testNow,
		"",
		nil,
		nil,
		domain.TokenReasonJWTProfile,
		nil,
		false,
		"",
		domain.OIDCResponseTypeUnspecified,
		opts...,
	)
}

func federatedSessionCommands(t *testing.T, es func(*testing.T) *eventstore.Eventstore, ids ...string) *Commands {
	c := &Commands{
		eventstore:                      es(t),
		idGenerator:                     mock.NewIDGeneratorExpectIDs(t, ids...),
		defaultAccessTokenLifetime:      12 * time.Hour,
		defaultRefreshTokenLifetime:     7 * 24 * time.Hour,
		defaultRefreshTokenIdleLifetime: 24 * time.Hour,
		keyAlgorithm:                    crypto.CreateMockEncryptionAlg(gomock.NewController(t)),
		authAlgorithm:                   &mockAuthCrypto{},
	}
	c.setMilestonesCompletedForTest("instanceID")
	return c
}

// TestCommands_CreateOIDCSession_federatedCredentialExchange pins what an exchange records: the
// exchanged event on the machine user, pushed together with the session it names, the distinct
// authentication method, and the credential's cap on the access token.
func TestCommands_CreateOIDCSession_federatedCredentialExchange(t *testing.T) {
	c := federatedSessionCommands(t, expectEventstore(
		expectFilter(testMachineAddedEvent()),
		expectFilterActiveOrg("org1"),
		expectFilter(), // token lifetime
		expectPush(federatedSessionPush(5*time.Minute)...),
	), "oidcSessionID", "accessTokenID")

	got, err := createFederatedSession(c,
		WithMaxAccessTokenLifetime(5*time.Minute),
		WithFederatedCredentialExchange(testFederatedCredentialExchange()),
	)
	require.NoError(t, err)
	assert.Equal(t, "V2_oidcSessionID-at_accessTokenID", got.TokenID)
	assert.Equal(t, "machine1", got.UserID)
	assert.Equal(t, []domain.UserAuthMethodType{domain.UserAuthMethodTypeFederatedCredential}, got.AuthMethods)
	assert.Equal(t, time.Time{}.Add(5*time.Minute), got.Expiration)
	assert.Empty(t, got.RefreshToken)
}

// A token that was exchanged before fails on its unique constraint; the push is refused as a whole,
// so no session or token is issued.
func TestCommands_CreateOIDCSession_federatedCredentialExchangeReplayed(t *testing.T) {
	used := zerrors.ThrowAlreadyExists(nil, "V3-DKcYh", "Errors.User.Machine.FederatedCredential.AssertionAlreadyUsed")
	c := federatedSessionCommands(t, expectEventstore(
		expectFilter(testMachineAddedEvent()),
		expectFilterActiveOrg("org1"),
		expectFilter(), // token lifetime
		expectPushFailed(used, federatedSessionPush(5*time.Minute)...),
	), "oidcSessionID", "accessTokenID")

	got, err := createFederatedSession(c,
		WithMaxAccessTokenLifetime(5*time.Minute),
		WithFederatedCredentialExchange(testFederatedCredentialExchange()),
	)
	require.Error(t, err)
	assert.True(t, zerrors.IsErrorAlreadyExists(err))
	assert.Nil(t, got)
}

// The mapped machine user must be active and not locked, and its organization active, as for a
// machine key: the exchange goes through the same check before anything is pushed.
func TestCommands_CreateOIDCSession_federatedCredentialExchangeUserState(t *testing.T) {
	tests := []struct {
		name    string
		expects []expect
		wantErr error
	}{
		{
			name: "deactivated machine user",
			expects: []expect{
				expectFilter(
					testMachineAddedEvent(),
					eventFromEventPusher(user.NewUserDeactivatedEvent(context.Background(), &user.NewAggregate("machine1", "org1").Aggregate)),
				),
			},
			wantErr: zerrors.ThrowPreconditionFailed(nil, "OIDCS-kj3g2", "Errors.User.NotActive"),
		},
		{
			name: "locked machine user",
			expects: []expect{
				expectFilter(
					testMachineAddedEvent(),
					eventFromEventPusher(user.NewUserLockedEvent(context.Background(), &user.NewAggregate("machine1", "org1").Aggregate)),
				),
			},
			wantErr: zerrors.ThrowPreconditionFailed(nil, "OIDCS-kj3g2", "Errors.User.NotActive"),
		},
		{
			name:    "removed machine user",
			expects: []expect{expectFilter()},
			wantErr: zerrors.ThrowPreconditionFailed(nil, "OIDCS-kj3g2", "Errors.User.NotActive"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := federatedSessionCommands(t, expectEventstore(tt.expects...))
			got, err := createFederatedSession(c,
				WithMaxAccessTokenLifetime(5*time.Minute),
				WithFederatedCredentialExchange(testFederatedCredentialExchange()),
			)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, got)
		})
	}
}

func TestOIDCSessionEvents_applyOptions_federatedCredentialExchange(t *testing.T) {
	events := &OIDCSessionEvents{
		oidcSessionWriteModel: NewOIDCSessionWriteModel("V2_oidcSessionID", "org1"),
		accessTokenLifetime:   time.Hour,
	}
	events.applyOptions(context.Background(), []OIDCSessionOption{WithFederatedCredentialExchange(testFederatedCredentialExchange())})

	require.Len(t, events.events, 1)
	exchanged, ok := events.events[0].(*user.MachineFederatedCredentialExchangedEvent)
	require.True(t, ok)
	assert.Equal(t, "machine1", exchanged.Aggregate().ID)
	assert.Equal(t, "org1", exchanged.Aggregate().ResourceOwner)
	assert.Equal(t, "V2_oidcSessionID", exchanged.OIDCSessionID)
	assert.Equal(t, "cred1", exchanged.CredentialID)
	assert.Equal(t, time.Hour, events.accessTokenLifetime, "the exchange alone caps nothing")
}
