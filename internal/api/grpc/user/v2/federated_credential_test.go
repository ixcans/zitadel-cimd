package user

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/pkg/grpc/user/v2"
)

// The RPCs only require an authenticated caller at the interceptor; the permission is checked
// against the target user in the command and query layers, as for the machine key RPCs.
func Test_federatedCredentialAuthMethods(t *testing.T) {
	for _, method := range []string{
		user.UserService_AddFederatedCredential_FullMethodName,
		user.UserService_UpdateFederatedCredential_FullMethodName,
		user.UserService_RemoveFederatedCredential_FullMethodName,
		user.UserService_ListFederatedCredentials_FullMethodName,
	} {
		option, ok := user.UserService_AuthMethods[method]
		assert.True(t, ok, method)
		assert.Equal(t, "authenticated", option.Permission, method)
	}
}

func Test_addFederatedCredentialRequestToDomain(t *testing.T) {
	tests := []struct {
		name string
		req  *user.AddFederatedCredentialRequest
		want *domain.FederatedCredential
	}{
		{
			name: "issuer metadata and pattern",
			req: &user.AddFederatedCredentialRequest{
				UserId:            "user1",
				Issuer:            "https://issuer.example.com",
				KeySource:         &user.FederatedCredentialKeySource{Source: &user.FederatedCredentialKeySource_IssuerMetadata{IssuerMetadata: &user.FederatedCredentialIssuerMetadataKeys{}}},
				AllowedAlgorithms: []string{"ES256", "RS256"},
				Audience:          "aud",
				SubjectRule: &user.FederatedCredentialSubjectRule{
					Claim: "sub",
					Match: &user.FederatedCredentialSubjectRule_Pattern{Pattern: "repo:acme/.+"},
				},
				ClaimConditions:  []*user.FederatedCredentialClaimCondition{{Claim: "env", Value: "prod"}},
				MaxTokenAge:      durationpb.New(10 * time.Minute),
				MaxTokenLifetime: durationpb.New(5 * time.Minute),
			},
			want: &domain.FederatedCredential{
				Issuer:           "https://issuer.example.com",
				KeySource:        domain.FederatedCredentialKeySourceIssuerMetadata,
				Algorithms:       []string{"ES256", "RS256"},
				Audience:         "aud",
				SubjectRule:      domain.FederatedCredentialSubjectRule{Claim: "sub", Pattern: "repo:acme/.+"},
				ClaimConditions:  []domain.FederatedCredentialClaimCondition{{Claim: "env", Value: "prod"}},
				MaxTokenAge:      10 * time.Minute,
				MaxTokenLifetime: 5 * time.Minute,
			},
		},
		{
			name: "pinned keys, exact subject, disabled",
			req: &user.AddFederatedCredentialRequest{
				Issuer:            "https://kubernetes.default.svc",
				KeySource:         &user.FederatedCredentialKeySource{Source: &user.FederatedCredentialKeySource_PinnedKeys{PinnedKeys: &user.FederatedCredentialPinnedKeys{Jwks: `{"keys":[]}`}}},
				AllowedAlgorithms: []string{"EdDSA"},
				Audience:          "aud",
				SubjectRule: &user.FederatedCredentialSubjectRule{
					Claim: "sub",
					Match: &user.FederatedCredentialSubjectRule_Exact{Exact: "system:serviceaccount:ci:deployer"},
				},
				MaxTokenAge:      durationpb.New(time.Hour),
				MaxTokenLifetime: durationpb.New(time.Hour),
				Disabled:         true,
			},
			want: &domain.FederatedCredential{
				Issuer:           "https://kubernetes.default.svc",
				KeySource:        domain.FederatedCredentialKeySourcePinnedKeys,
				PinnedKeys:       `{"keys":[]}`,
				Algorithms:       []string{"EdDSA"},
				Audience:         "aud",
				SubjectRule:      domain.FederatedCredentialSubjectRule{Claim: "sub", Exact: "system:serviceaccount:ci:deployer"},
				MaxTokenAge:      time.Hour,
				MaxTokenLifetime: time.Hour,
				Disabled:         true,
			},
		},
		{
			// Missing parts reach the command layer empty, where they are refused.
			name: "empty request",
			req:  &user.AddFederatedCredentialRequest{},
			want: &domain.FederatedCredential{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, addFederatedCredentialRequestToDomain(tt.req))
		})
	}
}

func Test_updateFederatedCredentialRequestToCommand(t *testing.T) {
	disabled := true
	audience := "aud2"
	issuer := "https://other.example.com"
	issuerMetadata := domain.FederatedCredentialKeySourceIssuerMetadata
	pinnedKeys := domain.FederatedCredentialKeySourcePinnedKeys
	tenMinutes := 10 * time.Minute
	tests := []struct {
		name string
		req  *user.UpdateFederatedCredentialRequest
		want *command.ChangeMachineFederatedCredential
	}{
		{
			name: "nothing set changes nothing",
			req:  &user.UpdateFederatedCredentialRequest{UserId: "user1", CredentialId: "cred1"},
			want: &command.ChangeMachineFederatedCredential{},
		},
		{
			name: "disable only",
			req:  &user.UpdateFederatedCredentialRequest{Disabled: &disabled},
			want: &command.ChangeMachineFederatedCredential{Disabled: &disabled},
		},
		{
			name: "empty conditions remove them",
			req:  &user.UpdateFederatedCredentialRequest{ClaimConditions: &user.FederatedCredentialClaimConditions{}},
			want: &command.ChangeMachineFederatedCredential{ClaimConditions: &[]domain.FederatedCredentialClaimCondition{}},
		},
		{
			name: "switch to issuer metadata",
			req: &user.UpdateFederatedCredentialRequest{
				KeySource: &user.FederatedCredentialKeySource{Source: &user.FederatedCredentialKeySource_IssuerMetadata{IssuerMetadata: &user.FederatedCredentialIssuerMetadataKeys{}}},
			},
			want: &command.ChangeMachineFederatedCredential{KeySource: &issuerMetadata},
		},
		{
			name: "every field",
			req: &user.UpdateFederatedCredentialRequest{
				Issuer:            &issuer,
				KeySource:         &user.FederatedCredentialKeySource{Source: &user.FederatedCredentialKeySource_PinnedKeys{PinnedKeys: &user.FederatedCredentialPinnedKeys{Jwks: "jwks"}}},
				AllowedAlgorithms: []string{"RS256"},
				Audience:          &audience,
				SubjectRule:       &user.FederatedCredentialSubjectRule{Claim: "oid", Match: &user.FederatedCredentialSubjectRule_Exact{Exact: "123"}},
				ClaimConditions: &user.FederatedCredentialClaimConditions{Conditions: []*user.FederatedCredentialClaimCondition{
					{Claim: "env", Value: "prod"},
				}},
				MaxTokenAge:      durationpb.New(tenMinutes),
				MaxTokenLifetime: durationpb.New(tenMinutes),
				Disabled:         &disabled,
			},
			want: &command.ChangeMachineFederatedCredential{
				Issuer:           &issuer,
				KeySource:        &pinnedKeys,
				PinnedKeys:       "jwks",
				Algorithms:       []string{"RS256"},
				Audience:         &audience,
				SubjectRule:      &domain.FederatedCredentialSubjectRule{Claim: "oid", Exact: "123"},
				ClaimConditions:  &[]domain.FederatedCredentialClaimCondition{{Claim: "env", Value: "prod"}},
				MaxTokenAge:      &tenMinutes,
				MaxTokenLifetime: &tenMinutes,
				Disabled:         &disabled,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, updateFederatedCredentialRequestToCommand(tt.req))
		})
	}
}

func Test_federatedCredentialToPb(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		credential *query.FederatedCredential
		want       *user.FederatedCredential
	}{
		{
			name: "issuer metadata, pattern, conditions",
			credential: &query.FederatedCredential{
				ID: "cred1", UserID: "user1", ResourceOwner: "org1", CreationDate: now, ChangeDate: now,
				FederatedCredential: domain.FederatedCredential{
					Issuer:           "https://issuer.example.com",
					KeySource:        domain.FederatedCredentialKeySourceIssuerMetadata,
					Algorithms:       []string{"ES256"},
					Audience:         "aud",
					SubjectRule:      domain.FederatedCredentialSubjectRule{Claim: "sub", Pattern: "repo:acme/.+"},
					ClaimConditions:  []domain.FederatedCredentialClaimCondition{{Claim: "env", Value: "prod"}},
					MaxTokenAge:      time.Minute,
					MaxTokenLifetime: 2 * time.Minute,
				},
			},
			want: &user.FederatedCredential{
				Id: "cred1", UserId: "user1", OrganizationId: "org1",
				CreationDate:      timestamppb.New(now),
				ChangeDate:        timestamppb.New(now),
				Issuer:            "https://issuer.example.com",
				KeySource:         &user.FederatedCredentialKeySource{Source: &user.FederatedCredentialKeySource_IssuerMetadata{IssuerMetadata: &user.FederatedCredentialIssuerMetadataKeys{}}},
				AllowedAlgorithms: []string{"ES256"},
				Audience:          "aud",
				SubjectRule:       &user.FederatedCredentialSubjectRule{Claim: "sub", Match: &user.FederatedCredentialSubjectRule_Pattern{Pattern: "repo:acme/.+"}},
				ClaimConditions:   []*user.FederatedCredentialClaimCondition{{Claim: "env", Value: "prod"}},
				MaxTokenAge:       durationpb.New(time.Minute),
				MaxTokenLifetime:  durationpb.New(2 * time.Minute),
			},
		},
		{
			name: "disabled, pinned keys, exact subject",
			credential: &query.FederatedCredential{
				ID: "cred2", UserID: "user1", ResourceOwner: "org1", CreationDate: now, ChangeDate: now,
				FederatedCredential: domain.FederatedCredential{
					Issuer:           "https://kubernetes.default.svc",
					KeySource:        domain.FederatedCredentialKeySourcePinnedKeys,
					PinnedKeys:       `{"keys":[]}`,
					Algorithms:       []string{"EdDSA"},
					Audience:         "aud",
					SubjectRule:      domain.FederatedCredentialSubjectRule{Claim: "sub", Exact: "system:serviceaccount:ci:deployer"},
					MaxTokenAge:      time.Hour,
					MaxTokenLifetime: time.Hour,
					Disabled:         true,
				},
			},
			want: &user.FederatedCredential{
				Id: "cred2", UserId: "user1", OrganizationId: "org1",
				CreationDate:      timestamppb.New(now),
				ChangeDate:        timestamppb.New(now),
				Issuer:            "https://kubernetes.default.svc",
				KeySource:         &user.FederatedCredentialKeySource{Source: &user.FederatedCredentialKeySource_PinnedKeys{PinnedKeys: &user.FederatedCredentialPinnedKeys{Jwks: `{"keys":[]}`}}},
				AllowedAlgorithms: []string{"EdDSA"},
				Audience:          "aud",
				SubjectRule:       &user.FederatedCredentialSubjectRule{Claim: "sub", Match: &user.FederatedCredentialSubjectRule_Exact{Exact: "system:serviceaccount:ci:deployer"}},
				MaxTokenAge:       durationpb.New(time.Hour),
				MaxTokenLifetime:  durationpb.New(time.Hour),
				Disabled:          true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, federatedCredentialToPb(tt.credential))
		})
	}
}
