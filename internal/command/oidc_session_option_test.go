package command

import (
	"context"
	"testing"
	"time"

	"github.com/muhlemmer/gu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/text/language"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/crypto"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/id/mock"
	"github.com/zitadel/zitadel/internal/repository/authrequest"
	"github.com/zitadel/zitadel/internal/repository/oidcsession"
	"github.com/zitadel/zitadel/internal/repository/session"
	"github.com/zitadel/zitadel/internal/repository/user"
)

func TestOIDCSessionEvents_applyOptions(t *testing.T) {
	tests := []struct {
		name       string
		configured time.Duration
		opts       []OIDCSessionOption
		want       time.Duration
	}{
		{"no option keeps the configured lifetime", 12 * time.Hour, nil, 12 * time.Hour},
		{"a longer configured lifetime is capped", 12 * time.Hour, []OIDCSessionOption{WithMaxAccessTokenLifetime(time.Hour)}, time.Hour},
		{"a shorter configured lifetime stays", 30 * time.Minute, []OIDCSessionOption{WithMaxAccessTokenLifetime(time.Hour)}, 30 * time.Minute},
		{"an equal configured lifetime stays", time.Hour, []OIDCSessionOption{WithMaxAccessTokenLifetime(time.Hour)}, time.Hour},
		{"a zero limit caps nothing", 12 * time.Hour, []OIDCSessionOption{WithMaxAccessTokenLifetime(0)}, 12 * time.Hour},
		{"a negative limit caps nothing", 12 * time.Hour, []OIDCSessionOption{WithMaxAccessTokenLifetime(-time.Hour)}, 12 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := &OIDCSessionEvents{
				accessTokenLifetime:      tt.configured,
				refreshTokenLifeTime:     7 * 24 * time.Hour,
				refreshTokenIdleLifetime: 24 * time.Hour,
			}
			events.applyOptions(tt.opts)
			assert.Equal(t, tt.want, events.accessTokenLifetime)
			assert.Equal(t, 7*24*time.Hour, events.refreshTokenLifeTime, "the refresh token lifetime is not capped")
			assert.Equal(t, 24*time.Hour, events.refreshTokenIdleLifetime, "the refresh token idle lifetime is not capped")
		})
	}
}

// TestCommands_CreateOIDCSessionFromAuthRequest_maxAccessTokenLifetime pins that the cap reaches
// the stored access token: the pushed event carries the capped lifetime, and the session's
// expiration (which becomes the token's exp and expires_in) follows it.
func TestCommands_CreateOIDCSessionFromAuthRequest_maxAccessTokenLifetime(t *testing.T) {
	tests := []struct {
		name       string
		configured time.Duration
		opts       []OIDCSessionOption
		want       time.Duration
	}{
		{"capped below the configured lifetime", 12 * time.Hour, []OIDCSessionOption{WithMaxAccessTokenLifetime(time.Hour)}, time.Hour},
		{"configured lifetime below the cap", 30 * time.Minute, []OIDCSessionOption{WithMaxAccessTokenLifetime(time.Hour)}, 30 * time.Minute},
		{"no option", 12 * time.Hour, nil, 12 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Commands{
				eventstore:                      expectEventstore(authRequestSessionEvents(tt.want)...)(t),
				idGenerator:                     mock.NewIDGeneratorExpectIDs(t, "oidcSessionID", "accessTokenID", "refreshTokenID"),
				defaultAccessTokenLifetime:      tt.configured,
				defaultRefreshTokenLifetime:     7 * 24 * time.Hour,
				defaultRefreshTokenIdleLifetime: 24 * time.Hour,
				keyAlgorithm:                    crypto.CreateMockEncryptionAlg(gomock.NewController(t)),
				authAlgorithm:                   &mockAuthCrypto{},
			}
			c.setMilestonesCompletedForTest("instanceID")
			got, _, err := c.CreateOIDCSessionFromAuthRequest(
				authz.WithInstanceID(context.Background(), "instanceID"),
				"V2_authRequestID",
				mockAuthRequestComplianceChecker(nil),
				true,
				"",
				tt.opts...,
			)
			require.NoError(t, err)
			assert.Equal(t, time.Time{}.Add(tt.want), got.Expiration)
		})
	}
}

// TestCommands_ExchangeOIDCSessionRefreshAndAccessToken_maxAccessTokenLifetime pins the cap on the
// access token issued by a refresh.
func TestCommands_ExchangeOIDCSessionRefreshAndAccessToken_maxAccessTokenLifetime(t *testing.T) {
	c := &Commands{
		eventstore: expectEventstore(
			expectFilter(
				eventFromEventPusherWithCreationDateNow(
					oidcsession.NewAddedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
						"userID", "org1", "sessionID", "clientID", []string{"audience"}, []string{"openid", "offline_access"},
						[]domain.UserAuthMethodType{domain.UserAuthMethodTypePassword}, testNow, "nonce", &language.Afrikaans,
						&domain.UserAgent{FingerprintID: gu.Ptr("browserFP")},
					),
				),
				eventFromEventPusherWithCreationDateNow(
					oidcsession.NewAccessTokenAddedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
						"at_accessTokenID", []string{"openid", "offline_access"}, time.Hour, domain.TokenReasonAuthRequest, nil),
				),
				eventFromEventPusherWithCreationDateNow(
					oidcsession.NewRefreshTokenAddedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
						"rt_refreshTokenID", 7*24*time.Hour, 24*time.Hour),
				),
			),
			expectFilter(), // no OrgDeactivated after refresh token issuance
			expectFilter(testHumanAddedEvent()),
			expectFilterActiveOrg("org1"),
			expectFilter(), // token lifetime
			expectPush(
				oidcsession.NewAccessTokenAddedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
					"at_accessTokenID", []string{"openid", "offline_access"}, time.Hour, domain.TokenReasonRefresh, nil),
				oidcsession.NewRefreshTokenRenewedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
					"rt_refreshTokenID2", 24*time.Hour),
			),
		)(t),
		idGenerator:                     mock.NewIDGeneratorExpectIDs(t, "accessTokenID", "refreshTokenID2"),
		defaultAccessTokenLifetime:      12 * time.Hour,
		defaultRefreshTokenLifetime:     7 * 24 * time.Hour,
		defaultRefreshTokenIdleLifetime: 24 * time.Hour,
		keyAlgorithm:                    crypto.CreateMockEncryptionAlg(gomock.NewController(t)),
		authAlgorithm:                   &mockAuthCrypto{},
	}
	got, err := c.ExchangeOIDCSessionRefreshAndAccessToken(
		authz.WithInstanceID(context.Background(), "instanceID"),
		"V2_oidcSessionID-rt_refreshTokenID:userID",
		[]string{"openid", "offline_access"},
		"clientID",
		mockRefreshTokenComplianceChecker(nil),
		WithMaxAccessTokenLifetime(time.Hour),
	)
	require.NoError(t, err)
	assert.Equal(t, time.Time{}.Add(time.Hour), got.Expiration)
}

// authRequestSessionEvents is the event history and push of a code exchange whose access token is
// issued with accessTokenLifetime.
func authRequestSessionEvents(accessTokenLifetime time.Duration) []expect {
	userAgent := &domain.UserAgent{FingerprintID: gu.Ptr("fp1")}
	return []expect{
		expectFilter(
			eventFromEventPusher(
				authrequest.NewAddedEvent(context.Background(), &authrequest.NewAggregate("V2_authRequestID", "instanceID").Aggregate,
					"loginClient",
					"clientID",
					"redirectURI",
					"state",
					"nonce",
					[]string{"openid", "offline_access"},
					[]string{"audience"},
					domain.OIDCResponseTypeCode,
					domain.OIDCResponseModeQuery,
					&domain.OIDCCodeChallenge{
						Challenge: "challenge",
						Method:    domain.CodeChallengeMethodS256,
					},
					nil,
					nil,
					nil,
					nil,
					nil,
					true,
					"issuer",
					"",
				),
			),
			eventFromEventPusher(
				authrequest.NewCodeAddedEvent(context.Background(), &authrequest.NewAggregate("V2_authRequestID", "instanceID").Aggregate),
			),
			eventFromEventPusher(
				authrequest.NewSessionLinkedEvent(context.Background(), &authrequest.NewAggregate("V2_authRequestID", "instanceID").Aggregate,
					"sessionID",
					"userID",
					testNow,
					[]domain.UserAuthMethodType{domain.UserAuthMethodTypePassword},
				),
			),
		),
		expectFilter(
			eventFromEventPusher(
				session.NewAddedEvent(context.Background(), &session.NewAggregate("sessionID", "instanceID").Aggregate, userAgent),
			),
			eventFromEventPusher(
				session.NewUserCheckedEvent(context.Background(), &session.NewAggregate("sessionID", "instanceID").Aggregate,
					"userID", "org1", testNow, &language.Afrikaans),
			),
			eventFromEventPusher(
				session.NewPasswordCheckedEvent(context.Background(), &session.NewAggregate("sessionID", "instanceID").Aggregate,
					testNow),
			),
		),
		expectFilter(testHumanAddedEvent()),
		expectFilterActiveOrg("org1"),
		expectFilter(), // token lifetime
		expectPush(
			authrequest.NewCodeExchangedEvent(context.Background(), &authrequest.NewAggregate("V2_authRequestID", "instanceID").Aggregate),
			oidcsession.NewAddedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
				"userID", "org1", "sessionID", "clientID", []string{"audience"}, []string{"openid", "offline_access"},
				[]domain.UserAuthMethodType{domain.UserAuthMethodTypePassword}, testNow, "nonce", &language.Afrikaans,
				userAgent,
			),
			oidcsession.NewAccessTokenAddedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
				"at_accessTokenID", []string{"openid", "offline_access"}, accessTokenLifetime, domain.TokenReasonAuthRequest, nil),
			oidcsession.NewRefreshTokenAddedEvent(context.Background(), &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate,
				"rt_refreshTokenID", 7*24*time.Hour, 24*time.Hour),
			authrequest.NewSucceededEvent(context.Background(), &authrequest.NewAggregate("V2_authRequestID", "instanceID").Aggregate),
		),
	}
}

func testHumanAddedEvent() eventstore.Event {
	return user.NewHumanAddedEvent(
		context.Background(),
		&user.NewAggregate("userID", "org1").Aggregate,
		"username",
		"firstname",
		"lastname",
		"nickname",
		"displayname",
		language.Afrikaans,
		domain.GenderUnspecified,
		"email",
		false,
	)
}
