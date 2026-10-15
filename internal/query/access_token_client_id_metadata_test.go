package query

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/oidcsession"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// TestQueries_ActiveAccessTokenByToken_clientIDMetadataDocumentRevoked pins that the access token of
// a session of a client resolved from a metadata document (its client ID is the document URL and it
// is not in the session's audience) is no longer active once the client revoked it or the refresh
// token issued with it. This is the check userinfo and introspection make.
func TestQueries_ActiveAccessTokenByToken_clientIDMetadataDocumentRevoked(t *testing.T) {
	const clientID = "https://app.example.com/oauth/client-metadata.json"
	aggregate := &oidcsession.NewAggregate("V2_oidcSessionID", "org1").Aggregate
	session := []eventstore.Event{
		eventFromEventPusherWithCreationDateNow(
			oidcsession.NewAddedEvent(context.Background(), aggregate,
				"userID", "org1", "sessionID", clientID, []string{"340000000000000001"}, []string{"openid", "offline_access"},
				[]domain.UserAuthMethodType{domain.UserAuthMethodTypePassword}, time.Now(), "nonce", &language.English, nil,
			),
		),
		eventFromEventPusherWithCreationDateNow(
			oidcsession.NewAccessTokenAddedEvent(context.Background(), aggregate,
				"at_accessTokenID", []string{"openid", "offline_access"}, time.Hour, domain.TokenReasonAuthRequest, nil),
		),
	}
	tests := []struct {
		name    string
		revoked eventstore.Command
	}{
		{"access token revoked", oidcsession.NewAccessTokenRevokedEvent(context.Background(), aggregate)},
		{"refresh token revoked", oidcsession.NewRefreshTokenRevokedEvent(context.Background(), aggregate)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &Queries{
				eventstore: expectEventstore(
					expectFilter(append(append([]eventstore.Event{}, session...), eventFromEventPusherWithCreationDateNow(tt.revoked))...),
				)(t),
			}
			got, err := q.ActiveAccessTokenByToken(context.Background(), "V2_oidcSessionID-at_accessTokenID")
			require.ErrorIs(t, err, zerrors.ThrowUnauthenticated(nil, "QUERY-M2u9w", "Errors.OIDCSession.Token.Invalid"))
			assert.Nil(t, got)
		})
	}
}
