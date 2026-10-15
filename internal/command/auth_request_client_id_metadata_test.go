package command

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/muhlemmer/gu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/authrequest"
	"github.com/zitadel/zitadel/internal/repository/session"
	"github.com/zitadel/zitadel/internal/zerrors"
)

const testClientIDMetadataDocumentURL = "https://app.example.com/oauth/client-metadata.json"

func TestAuthRequestClientHasProject(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		want     bool
	}{
		{"metadata document client", testClientIDMetadataDocumentURL, false},
		{"metadata document client with port and query", "https://app.example.com:8443/client?v=1", false},
		{"generated client id", "312909075212468632", true},
		{"generated client id with project suffix", "312909075212468632@project", true},
		{"plain string", "clientID", true},
		{"empty", "", true},
		// Not a valid metadata document URL, so never resolved from a document: the check runs and,
		// as for any unknown client, fails closed.
		{"http url", "http://app.example.com/client", true},
		{"https url without path", "https://app.example.com", true},
		{"https url with fragment", "https://app.example.com/client#x", true},
		{"https url with userinfo", "https://user@app.example.com/client", true},
		{"https url with dot segment", "https://app.example.com/a/../client", true},
		{"https url too long", "https://app.example.com/" + strings.Repeat("a", domain.MaxClientIDMetadataDocumentURLLength), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, authRequestClientHasProject(tt.clientID))
		})
	}
}

// TestCommands_LinkSessionToAuthRequest_clientIDMetadataDocument pins that linking a session to the
// auth request of a client resolved from a metadata document does not run the project permission
// check, which looks the client up as a registered application and cannot find one, while every
// other client is still checked and still refused when the check fails.
func TestCommands_LinkSessionToAuthRequest_clientIDMetadataDocument(t *testing.T) {
	mockCtx := authz.NewMockContext("instanceID", "orgID", "loginClient")
	authRequestAdded := func(clientID string) eventstore.Event {
		return eventFromEventPusher(
			authrequest.NewAddedEvent(mockCtx, &authrequest.NewAggregate("V2_id", "instanceID").Aggregate,
				"loginClient",
				clientID,
				"redirectURI",
				"state",
				"nonce",
				[]string{"openid"},
				nil,
				domain.OIDCResponseTypeCode,
				domain.OIDCResponseModeQuery,
				&domain.OIDCCodeChallenge{Challenge: "challenge", Method: domain.CodeChallengeMethodS256},
				nil,
				nil,
				nil,
				nil,
				nil,
				false,
				"issuer",
				"",
			),
		)
	}
	activeSession := expectFilter(
		eventFromEventPusher(
			session.NewAddedEvent(mockCtx,
				&session.NewAggregate("sessionID", "instance1").Aggregate,
				&domain.UserAgent{
					FingerprintID: gu.Ptr("fp1"),
					IP:            net.ParseIP("1.2.3.4"),
					Description:   gu.Ptr("firefox"),
					Header:        http.Header{"foo": []string{"bar"}},
				},
			)),
		eventFromEventPusher(
			session.NewUserCheckedEvent(mockCtx, &session.NewAggregate("sessionID", "instance1").Aggregate,
				"userID", "org1", testNow, &language.Afrikaans),
		),
		eventFromEventPusher(
			session.NewPasswordCheckedEvent(mockCtx, &session.NewAggregate("sessionID", "instance1").Aggregate,
				testNow),
		),
		eventFromEventPusherWithCreationDateNow(
			session.NewLifetimeSetEvent(mockCtx, &session.NewAggregate("sessionID", "instance1").Aggregate,
				2*time.Minute),
		),
	)
	sessionLinked := expectPush(
		authrequest.NewSessionLinkedEvent(mockCtx, &authrequest.NewAggregate("V2_id", "instanceID").Aggregate,
			"sessionID",
			"userID",
			testNow,
			[]domain.UserAuthMethodType{domain.UserAuthMethodTypePassword},
		),
	)
	linkedAuthRequest := func(clientID string) *CurrentAuthRequest {
		return &CurrentAuthRequest{
			AuthRequest: &AuthRequest{
				ID:            "V2_id",
				LoginClient:   "loginClient",
				ClientID:      clientID,
				RedirectURI:   "redirectURI",
				State:         "state",
				Nonce:         "nonce",
				Scope:         []string{"openid"},
				ResponseType:  domain.OIDCResponseTypeCode,
				ResponseMode:  domain.OIDCResponseModeQuery,
				CodeChallenge: &domain.OIDCCodeChallenge{Challenge: "challenge", Method: domain.CodeChallengeMethodS256},
				Issuer:        "issuer",
			},
			SessionID:   "sessionID",
			UserID:      "userID",
			AuthMethods: []domain.UserAuthMethodType{domain.UserAuthMethodTypePassword},
		}
	}

	type call struct{ clientID, userID string }
	tests := []struct {
		name            string
		clientID        string
		eventstore      func(*testing.T) *eventstore.Eventstore
		checkErr        error
		wantCalls       []call
		wantErr         error
		wantAuthRequest *CurrentAuthRequest
	}{
		{
			// The check would fail exactly as it did for such a client before: the application
			// lookup finds no row. It must not be reached.
			name:            "metadata document client is linked without the project check",
			clientID:        testClientIDMetadataDocumentURL,
			eventstore:      expectEventstore(expectFilter(authRequestAdded(testClientIDMetadataDocumentURL)), activeSession, sessionLinked),
			checkErr:        zerrors.ThrowNotFound(nil, "QUERY-4tq8wCTCgf", "Errors.App.NotFound"),
			wantCalls:       nil,
			wantAuthRequest: linkedAuthRequest(testClientIDMetadataDocumentURL),
		},
		{
			name:            "registered client passing the check is linked",
			clientID:        "312909075212468632",
			eventstore:      expectEventstore(expectFilter(authRequestAdded("312909075212468632")), activeSession, sessionLinked),
			wantCalls:       []call{{"312909075212468632", "userID"}},
			wantAuthRequest: linkedAuthRequest("312909075212468632"),
		},
		{
			name:       "registered client failing the check is refused",
			clientID:   "312909075212468632",
			eventstore: expectEventstore(expectFilter(authRequestAdded("312909075212468632")), activeSession),
			checkErr:   zerrors.ThrowPermissionDenied(nil, "OIDC-foSyH49RvL", "Errors.User.GrantRequired"),
			wantCalls:  []call{{"312909075212468632", "userID"}},
			wantErr:    zerrors.ThrowPermissionDenied(nil, "OIDC-foSyH49RvL", "Errors.User.GrantRequired"),
		},
		{
			// An URL that is not a valid client_id URL is never resolved from a document, so it is
			// treated like any other client ID and checked.
			name:       "http url client failing the check is refused",
			clientID:   "http://app.example.com/client",
			eventstore: expectEventstore(expectFilter(authRequestAdded("http://app.example.com/client")), activeSession),
			checkErr:   zerrors.ThrowNotFound(nil, "QUERY-4tq8wCTCgf", "Errors.App.NotFound"),
			wantCalls:  []call{{"http://app.example.com/client", "userID"}},
			wantErr:    zerrors.ThrowNotFound(nil, "QUERY-4tq8wCTCgf", "Errors.App.NotFound"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []call
			projectPermissionCheck := func(_ context.Context, clientID, userID string) error {
				calls = append(calls, call{clientID, userID})
				return tt.checkErr
			}
			c := &Commands{
				eventstore:           tt.eventstore(t),
				sessionTokenVerifier: newMockTokenVerifierValid(),
				checkPermission:      newMockPermissionCheckAllowed(),
			}
			details, got, err := c.LinkSessionToAuthRequest(authz.NewMockContext("instanceID", "orgID", "loginClient"), "V2_id", "sessionID", "token", true, projectPermissionCheck)
			assert.Equal(t, tt.wantCalls, calls)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assertObjectDetails(t, &domain.ObjectDetails{ResourceOwner: "instanceID"}, details)
			assert.WithinRange(t, got.AuthTime, testNow, testNow)
			got.AuthTime = time.Time{}
			assert.Equal(t, tt.wantAuthRequest, got)
		})
	}
}
