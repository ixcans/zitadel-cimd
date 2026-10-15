package oidc

import (
	"context"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
)

// clientIDMetadataDocumentScopeAndAudience applies the scope policy for clients resolved from a
// Client ID Metadata Document to the scopes of an authorization request, with the instance in
// ctx: its own project and the projects it allows as an audience of such clients.
func clientIDMetadataDocumentScopeAndAudience(ctx context.Context, reqScope []string) (scope, audience []string, err error) {
	instance := authz.GetInstance(ctx)
	allowedAudiences := instance.ClientIDMetadataDocumentAllowedAudiences()
	return cimdScopeAndAudience(reqScope, instance.ProjectID(), func(projectID string) bool {
		return slices.Contains(allowedAudiences, projectID)
	})
}

// cimdScopeAndAudience is the scope policy for clients resolved from a Client ID Metadata
// Document. Such a client is described by a document anyone can publish, so by default it
// receives an identity assertion and nothing else; it gets a project as an audience only when
// the project is opted in. The policy applies to every such client alike, because a document
// carries no per-client policy.
//
// It returns the scopes to store on the authorization request and the audience they grant:
//
//   - openid, profile and email are kept.
//   - The organization scopes (urn:zitadel:iam:org:id:{id}, urn:zitadel:iam:org:domain:primary:{domain})
//     are kept. They only restrict who may sign in; the caller asserts them as for any client.
//   - A project audience scope (urn:zitadel:iam:org:project:id:{id}:aud) is kept, and the project
//     added to the audience, only when audienceAllowed reports the project as opted in. The
//     ZITADEL project, named as "zitadel" or by instanceProjectID, is never an audience. A request
//     for any audience that is not granted fails with invalid_scope instead of being dropped, so
//     a client never believes it holds an audience it does not.
//   - offline_access is kept only when an audience is granted, so a client that only signs a user
//     in gets no refresh token.
//   - Every other scope is dropped without an error: role scopes (project roles and
//     urn:zitadel:iam:org:projects:roles), user metadata, resource owner, identity provider and
//     organization roles scopes, phone, address and any custom scope.
func cimdScopeAndAudience(reqScope []string, instanceProjectID string, audienceAllowed func(projectID string) bool) (scope, audience []string, err error) {
	offlineAccess := false
	for _, s := range reqScope {
		switch {
		case s == oidc.ScopeOpenID, s == oidc.ScopeProfile, s == oidc.ScopeEmail:
			scope = appendOnce(scope, s)
		case strings.HasPrefix(s, domain.OrgIDScope), strings.HasPrefix(s, domain.OrgDomainPrimaryScope):
			scope = appendOnce(scope, s)
		case s == oidc.ScopeOfflineAccess:
			offlineAccess = true
		default:
			projectID, ok := audienceScopeProjectID(s)
			if !ok {
				continue
			}
			if projectID == domain.ProjectIDScopeZITADEL || projectID == instanceProjectID {
				return nil, nil, oidc.ErrInvalidScope().WithDescription("The ZITADEL API cannot be requested as an audience by this client")
			}
			if !audienceAllowed(projectID) {
				// The project ID is not echoed: it is client input, and the description is
				// returned on the redirect.
				return nil, nil, oidc.ErrInvalidScope().WithDescription("A requested audience is not allowed for this client")
			}
			scope = appendOnce(scope, s)
			audience = appendOnce(audience, projectID)
		}
	}
	if offlineAccess && len(audience) > 0 {
		scope = appendOnce(scope, oidc.ScopeOfflineAccess)
	}
	return scope, audience, nil
}

// audienceScopeProjectID returns the project ID of a project audience scope
// (urn:zitadel:iam:org:project:id:{id}:aud), read exactly as the audience of a token is.
func audienceScopeProjectID(scope string) (string, bool) {
	if !strings.HasPrefix(scope, domain.ProjectIDScope) || !strings.HasSuffix(scope, domain.AudSuffix) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(scope, domain.ProjectIDScope), domain.AudSuffix), true
}

func appendOnce(list []string, value string) []string {
	if slices.Contains(list, value) {
		return list
	}
	return append(list, value)
}
