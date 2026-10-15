package command

import (
	"context"
	"testing"
	"time"

	"github.com/muhlemmer/gu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/oidcsession"
	"github.com/zitadel/zitadel/internal/zerrors"
)

const (
	testOtherClientIDMetadataDocumentURL = "https://other.example.com/oauth/client-metadata.json"
	testRegisteredClientID               = "312909075212468632"
	testListedAudienceProjectID          = "340000000000000001"
)

func TestSessionOwnedByMetadataDocumentClient(t *testing.T) {
	tests := []struct {
		name            string
		sessionClientID string
		clientID        string
		want            bool
	}{
		{"metadata document client of the session", testClientIDMetadataDocumentURL, testClientIDMetadataDocumentURL, true},
		{"another metadata document client", testClientIDMetadataDocumentURL, testOtherClientIDMetadataDocumentURL, false},
		{"registered client against a metadata document client's session", testClientIDMetadataDocumentURL, testRegisteredClientID, false},
		{"registered client of the session", testRegisteredClientID, testRegisteredClientID, false},
		{"http url client of the session", "http://app.example.com/client", "http://app.example.com/client", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sessionOwnedByMetadataDocumentClient(tt.sessionClientID, tt.clientID))
		})
	}
}

// TestCommands_RevokeOIDCSessionToken_clientIDMetadataDocument pins that a client resolved from a
// metadata document can revoke the access and refresh tokens of its own session (RFC 7009), although
// it is never in the session's audience, that the revoked token then fails the session check, and
// that no other client gains anything: another metadata document client and a registered client are
// refused, and a registered client is still judged by the audience alone.
func TestCommands_RevokeOIDCSessionToken_clientIDMetadataDocument(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "instanceID")
	aggregate := &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate
	scope := []string{"openid", "profile", "offline_access"}
	sessionAdded := func(clientID string, audience []string) eventstore.Event {
		return eventFromEventPusher(
			oidcsession.NewAddedEvent(context.Background(), aggregate,
				"userID", "org1", "sessionID", clientID, audience, scope,
				[]domain.UserAuthMethodType{domain.UserAuthMethodTypePassword}, testNow, "nonce", &language.Afrikaans,
				&domain.UserAgent{FingerprintID: gu.Ptr("browserFP")},
			),
		)
	}
	accessTokenAdded := eventFromEventPusherWithCreationDateNow(
		oidcsession.NewAccessTokenAddedEvent(context.Background(), aggregate,
			"at_accessTokenID", scope, time.Hour, domain.TokenReasonAuthRequest, nil),
	)
	refreshTokenAdded := eventFromEventPusherWithCreationDateNow(
		oidcsession.NewRefreshTokenAddedEvent(context.Background(), aggregate,
			"rt_refreshTokenID", 7*24*time.Hour, 24*time.Hour),
	)
	invalidClient := zerrors.ThrowPreconditionFailed(nil, "OIDCS-SKjl3", "Errors.OIDCSession.InvalidClient")

	tests := []struct {
		name     string
		session  []eventstore.Event
		token    string
		clientID string
		// revoked is the event the revocation pushes, nil when it is refused.
		revoked eventstore.Command
		wantErr error
	}{
		{
			name:     "metadata document client revokes its access token",
			session:  []eventstore.Event{sessionAdded(testClientIDMetadataDocumentURL, nil), accessTokenAdded},
			token:    "V2_oidcSessionID-at_accessTokenID",
			clientID: testClientIDMetadataDocumentURL,
			revoked:  oidcsession.NewAccessTokenRevokedEvent(context.Background(), aggregate),
		},
		{
			// A refresh token is issued only together with a granted audience, so this session has one.
			name:     "metadata document client revokes its refresh token",
			session:  []eventstore.Event{sessionAdded(testClientIDMetadataDocumentURL, []string{testListedAudienceProjectID}), accessTokenAdded, refreshTokenAdded},
			token:    "V2_oidcSessionID-rt_refreshTokenID",
			clientID: testClientIDMetadataDocumentURL,
			revoked:  oidcsession.NewRefreshTokenRevokedEvent(context.Background(), aggregate),
		},
		{
			name:     "another metadata document client cannot revoke the access token",
			session:  []eventstore.Event{sessionAdded(testClientIDMetadataDocumentURL, []string{testListedAudienceProjectID}), accessTokenAdded, refreshTokenAdded},
			token:    "V2_oidcSessionID-at_accessTokenID",
			clientID: testOtherClientIDMetadataDocumentURL,
			wantErr:  invalidClient,
		},
		{
			name:     "another metadata document client cannot revoke the refresh token",
			session:  []eventstore.Event{sessionAdded(testClientIDMetadataDocumentURL, []string{testListedAudienceProjectID}), accessTokenAdded, refreshTokenAdded},
			token:    "V2_oidcSessionID-rt_refreshTokenID",
			clientID: testOtherClientIDMetadataDocumentURL,
			wantErr:  invalidClient,
		},
		{
			name:     "registered client cannot revoke a metadata document client's token",
			session:  []eventstore.Event{sessionAdded(testClientIDMetadataDocumentURL, []string{testListedAudienceProjectID}), accessTokenAdded},
			token:    "V2_oidcSessionID-at_accessTokenID",
			clientID: testRegisteredClientID,
			wantErr:  invalidClient,
		},
		{
			name:     "registered client in the audience revokes as before",
			session:  []eventstore.Event{sessionAdded(testRegisteredClientID, []string{testRegisteredClientID, testListedAudienceProjectID}), accessTokenAdded},
			token:    "V2_oidcSessionID-at_accessTokenID",
			clientID: testRegisteredClientID,
			revoked:  oidcsession.NewAccessTokenRevokedEvent(context.Background(), aggregate),
		},
		{
			// Unchanged upstream behaviour: a registered client is judged by the audience alone, even
			// when it is the session's own client.
			name:     "registered client of the session but not in its audience is still refused",
			session:  []eventstore.Event{sessionAdded(testRegisteredClientID, []string{testListedAudienceProjectID}), accessTokenAdded},
			token:    "V2_oidcSessionID-at_accessTokenID",
			clientID: testRegisteredClientID,
			wantErr:  invalidClient,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expects := []expect{expectFilter(tt.session...)}
			if tt.revoked != nil {
				expects = append(expects, expectPush(tt.revoked))
			}
			c := &Commands{eventstore: expectEventstore(expects...)(t)}
			err := c.RevokeOIDCSessionToken(ctx, tt.token, tt.clientID)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}

	// The refresh grant checks the refresh token on this write model, so a revoked refresh token is
	// refused from then on, and so is the access token issued with it.
	t.Run("a revoked refresh token then fails the session check", func(t *testing.T) {
		events := []eventstore.Event{sessionAdded(testClientIDMetadataDocumentURL, []string{testListedAudienceProjectID}), accessTokenAdded, refreshTokenAdded}
		before := NewOIDCSessionWriteModel("V2_oidcSessionID", "")
		require.NoError(t, expectEventstore(expectFilter(events...))(t).FilterToQueryReducer(ctx, before))
		require.NoError(t, before.CheckRefreshToken("rt_refreshTokenID"))
		require.NoError(t, before.CheckAccessToken("at_accessTokenID"))

		after := NewOIDCSessionWriteModel("V2_oidcSessionID", "")
		revoked := eventFromEventPusherWithCreationDateNow(oidcsession.NewRefreshTokenRevokedEvent(context.Background(), aggregate))
		require.NoError(t, expectEventstore(expectFilter(append(events, revoked)...))(t).FilterToQueryReducer(ctx, after))
		assert.Error(t, after.CheckRefreshToken("rt_refreshTokenID"))
		assert.Error(t, after.CheckAccessToken("at_accessTokenID"))
	})
}
