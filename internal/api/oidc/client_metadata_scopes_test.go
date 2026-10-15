package oidc

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/query"
)

const (
	cimdTestInstanceProject = "100000000000000001"
	cimdTestListedProject   = "200000000000000002"
	cimdTestUnlistedProject = "300000000000000003"
)

func cimdTestAudienceScope(projectID string) string {
	return "urn:zitadel:iam:org:project:id:" + projectID + ":aud"
}

// cimdTestListed opts in only cimdTestListedProject.
func cimdTestListed(projectID string) bool {
	return projectID == cimdTestListedProject
}

// cimdTestListsEverything opts in every project, so a refusal can only come from the rule that
// the ZITADEL project is never an audience.
func cimdTestListsEverything(string) bool {
	return true
}

func requireInvalidScope(t *testing.T, err error) {
	t.Helper()
	var oidcErr *oidc.Error
	require.ErrorAs(t, err, &oidcErr)
	assert.Equal(t, oidc.InvalidScope, oidcErr.ErrorType)
}

func TestCIMDScopeAndAudience(t *testing.T) {
	tests := []struct {
		name            string
		reqScope        []string
		audienceAllowed func(string) bool
		wantScope       []string
		wantAudience    []string
		wantInvalid     bool
	}{
		{
			name:            "identity scopes are kept",
			reqScope:        []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
			audienceAllowed: cimdTestListed,
			wantScope:       []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
		},
		{
			name:            "organization routing scopes are kept",
			reqScope:        []string{oidc.ScopeOpenID, "urn:zitadel:iam:org:id:400000000000000004", "urn:zitadel:iam:org:domain:primary:acme.example.com"},
			audienceAllowed: cimdTestListed,
			wantScope:       []string{oidc.ScopeOpenID, "urn:zitadel:iam:org:id:400000000000000004", "urn:zitadel:iam:org:domain:primary:acme.example.com"},
		},
		{
			name: "role, metadata, resource owner, identity provider, organization roles, phone, address and custom scopes are dropped",
			reqScope: []string{
				oidc.ScopeOpenID,
				ScopeProjectsRoles,
				ScopeProjectRolePrefix + "admin",
				ScopeUserMetaData,
				ScopeResourceOwner,
				"urn:zitadel:iam:org:idp:id:500000000000000005",
				"urn:zitadel:iam:org:roles:id:400000000000000004",
				oidc.ScopePhone,
				oidc.ScopeAddress,
				"custom",
				"urn:zitadel:iam:org:project:id:" + cimdTestListedProject,
			},
			audienceAllowed: cimdTestListsEverything,
			wantScope:       []string{oidc.ScopeOpenID},
		},
		{
			name:            "listed project is granted as an audience",
			reqScope:        []string{oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestListedProject)},
			audienceAllowed: cimdTestListed,
			wantScope:       []string{oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestListedProject)},
			wantAudience:    []string{cimdTestListedProject},
		},
		{
			name:            "unlisted project is refused",
			reqScope:        []string{oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestUnlistedProject)},
			audienceAllowed: cimdTestListed,
			wantInvalid:     true,
		},
		{
			name:            "a listed and an unlisted project are refused together",
			reqScope:        []string{oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestListedProject), cimdTestAudienceScope(cimdTestUnlistedProject)},
			audienceAllowed: cimdTestListed,
			wantInvalid:     true,
		},
		{
			name:            "zitadel project by its reserved name is refused, even if listed",
			reqScope:        []string{oidc.ScopeOpenID, "urn:zitadel:iam:org:project:id:zitadel:aud"},
			audienceAllowed: cimdTestListsEverything,
			wantInvalid:     true,
		},
		{
			name:            "zitadel project by the instance's project id is refused, even if listed",
			reqScope:        []string{oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestInstanceProject)},
			audienceAllowed: cimdTestListsEverything,
			wantInvalid:     true,
		},
		{
			name:            "empty project id is refused",
			reqScope:        []string{oidc.ScopeOpenID, "urn:zitadel:iam:org:project:id::aud"},
			audienceAllowed: cimdTestListed,
			wantInvalid:     true,
		},
		{
			name:            "offline_access without an audience is dropped",
			reqScope:        []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
			audienceAllowed: cimdTestListed,
			wantScope:       []string{oidc.ScopeOpenID},
		},
		{
			name:            "offline_access with a granted audience is kept, whatever its position",
			reqScope:        []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestListedProject)},
			audienceAllowed: cimdTestListed,
			wantScope:       []string{oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestListedProject), oidc.ScopeOfflineAccess},
			wantAudience:    []string{cimdTestListedProject},
		},
		{
			name:            "repeated scopes are kept once",
			reqScope:        []string{oidc.ScopeOpenID, oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestListedProject), cimdTestAudienceScope(cimdTestListedProject)},
			audienceAllowed: cimdTestListed,
			wantScope:       []string{oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestListedProject)},
			wantAudience:    []string{cimdTestListedProject},
		},
		{
			name:            "no scopes",
			audienceAllowed: cimdTestListed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, audience, err := cimdScopeAndAudience(tt.reqScope, cimdTestInstanceProject, tt.audienceAllowed)
			if tt.wantInvalid {
				requireInvalidScope(t, err)
				assert.Nil(t, scope)
				assert.Nil(t, audience)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantScope, scope)
			assert.Equal(t, tt.wantAudience, audience)
		})
	}
}

// TestCreateAuthRequestScopeAndAudience_clientIDMetadataDocument pins that the authorization
// request of a client resolved from a Client ID Metadata Document goes through the scope
// policy with the instance's own project and its list of allowed audiences.
func TestCreateAuthRequestScopeAndAudience_clientIDMetadataDocument(t *testing.T) {
	const clientID = "https://app.example.com/client"
	storage := &OPStorage{
		clientIDMetadataResolver: newClientIDMetadataResolver(http.DefaultClient, clientIDMetadataAllowlist{allowAny: true}, nil, time.Hour, time.Hour, nil),
	}
	ctx := func(allowedAudiences ...string) context.Context {
		return authz.NewMockContext("instance", "org", "",
			authz.WithMockProjectID(cimdTestInstanceProject),
			authz.WithMockClientIDMetadataDocument(true),
			authz.WithMockClientIDMetadataDocumentAllowedURLs(clientID),
			authz.WithMockClientIDMetadataDocumentAllowedAudiences(allowedAudiences...),
		)
	}
	reqScope := []string{oidc.ScopeOpenID, oidc.ScopeProfile, ScopeProjectsRoles, oidc.ScopeOfflineAccess, cimdTestAudienceScope(cimdTestListedProject)}

	t.Run("listed audience granted, roles dropped", func(t *testing.T) {
		scope, audience, orgID, err := storage.createAuthRequestScopeAndAudience(ctx(cimdTestListedProject), clientID, reqScope)
		require.NoError(t, err)
		assert.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeProfile, cimdTestAudienceScope(cimdTestListedProject), oidc.ScopeOfflineAccess}, scope)
		assert.Equal(t, []string{cimdTestListedProject}, audience)
		assert.Empty(t, orgID)
	})
	t.Run("audience not on the instance's list, invalid_scope", func(t *testing.T) {
		_, _, _, err := storage.createAuthRequestScopeAndAudience(ctx(cimdTestUnlistedProject), clientID, reqScope)
		requireInvalidScope(t, err)
	})
	t.Run("zitadel audience, invalid_scope even if listed", func(t *testing.T) {
		_, _, _, err := storage.createAuthRequestScopeAndAudience(ctx(cimdTestInstanceProject), clientID, []string{oidc.ScopeOpenID, cimdTestAudienceScope(cimdTestInstanceProject)})
		requireInvalidScope(t, err)
		_, _, _, err = storage.createAuthRequestScopeAndAudience(ctx(cimdTestInstanceProject), clientID, []string{oidc.ScopeOpenID, "urn:zitadel:iam:org:project:id:zitadel:aud"})
		requireInvalidScope(t, err)
	})
	t.Run("identity only, no refresh token", func(t *testing.T) {
		scope, audience, _, err := storage.createAuthRequestScopeAndAudience(ctx(), clientID, []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeOfflineAccess})
		require.NoError(t, err)
		assert.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeEmail}, scope)
		assert.Empty(t, audience)
		assert.False(t, slices.Contains(scope, oidc.ScopeOfflineAccess), "the auth request must not need a refresh token")
	})
}

// TestUserinfo_clientIDMetadataDocumentRoles exercises how the userinfo endpoint builds role and
// organization claims for a token of a client resolved from a Client ID Metadata Document. Such a
// client is not in the database, so UserInfo passes no project and no project role assertion
// (GetOIDCUserinfoClientByID finds nothing), and asserts roles for the projects the token's
// scope names. With the scopes as requested, that reads the user's roles in any project; with
// the scopes the policy stores, it reads none.
func TestUserinfo_clientIDMetadataDocumentRoles(t *testing.T) {
	grants := []query.UserGrant{
		{ProjectID: cimdTestListedProject, Roles: []string{"admin"}, ResourceOwner: "400000000000000004", OrgPrimaryDomain: "acme.example.com"},
		{ProjectID: cimdTestUnlistedProject, Roles: []string{"viewer"}, ResourceOwner: "400000000000000004", OrgPrimaryDomain: "acme.example.com"},
		{ProjectID: cimdTestInstanceProject, Roles: []string{"IAM_OWNER"}, ResourceOwner: "400000000000000004", OrgPrimaryDomain: "acme.example.com"},
	}
	user := &query.OIDCUserInfo{
		User: &query.User{ID: "user"},
		Metadata: []query.UserMetadata{
			{Key: "department", Value: []byte("finance")},
		},
		Org: &query.UserInfoOrg{ID: "400000000000000004", Name: "acme", PrimaryDomain: "acme.example.com"},
	}
	// userinfoClaims mirrors Server.UserInfo for a token whose client has no project: the
	// role audience comes from the scope, and the query returns the grants of those projects.
	userinfoClaims := func(t *testing.T, scope []string) map[string]any {
		t.Helper()
		roleAudience, requestedRoles := prepareRoles(authz.NewMockContext("instance", "org", "", authz.WithMockProjectID(cimdTestInstanceProject)), scope, "", false, false)
		u := *user
		u.UserGrants = nil
		for _, grant := range grants {
			if slices.Contains(roleAudience, grant.ProjectID) {
				u.UserGrants = append(u.UserGrants, grant)
			}
		}
		info := userInfoToOIDC(&u, true, scope, "")
		assertRoles("", &u, roleAudience, requestedRoles, true, info)
		return info.Claims
	}
	roleScopes := []string{
		oidc.ScopeOpenID,
		ScopeProjectsRoles,
		ScopeUserMetaData,
		ScopeResourceOwner,
		cimdTestAudienceScope(cimdTestUnlistedProject),
		"urn:zitadel:iam:org:project:id:zitadel:aud",
	}

	t.Run("scopes as requested read roles of any project", func(t *testing.T) {
		claims := userinfoClaims(t, roleScopes)
		assert.Contains(t, claims, "urn:zitadel:iam:org:project:"+cimdTestUnlistedProject+":roles")
		assert.Contains(t, claims, "urn:zitadel:iam:org:project:"+cimdTestInstanceProject+":roles")
		assert.Contains(t, claims, ClaimUserMetaData)
	})
	t.Run("identity-only request, no roles, metadata or organization claims", func(t *testing.T) {
		identityOnly := slices.DeleteFunc(slices.Clone(roleScopes), func(s string) bool {
			_, isAudience := audienceScopeProjectID(s)
			return isAudience
		})
		scope, audience, err := cimdScopeAndAudience(append(identityOnly, oidc.ScopeProfile, oidc.ScopeEmail), cimdTestInstanceProject, cimdTestListed)
		require.NoError(t, err)
		require.Empty(t, audience)
		assertNoRoleOrOrganizationClaims(t, userinfoClaims(t, scope))
	})
	t.Run("listed audience, still no roles", func(t *testing.T) {
		scope, audience, err := cimdScopeAndAudience([]string{oidc.ScopeOpenID, ScopeProjectsRoles, ScopeProjectRolePrefix + "admin", cimdTestAudienceScope(cimdTestListedProject)}, cimdTestInstanceProject, cimdTestListed)
		require.NoError(t, err)
		require.Equal(t, []string{cimdTestListedProject}, audience)
		assertNoRoleOrOrganizationClaims(t, userinfoClaims(t, scope))
	})
}

func assertNoRoleOrOrganizationClaims(t *testing.T, claims map[string]any) {
	t.Helper()
	for claim := range claims {
		assert.NotContains(t, claim, ":roles", "role claim %s", claim)
		assert.NotEqual(t, ClaimUserMetaData, claim)
		assert.NotContains(t, claim, "resourceowner", "resource owner claim %s", claim)
	}
}
