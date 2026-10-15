package user

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zitadel/zitadel/internal/api/grpc/filter/v2"
	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/internal/zerrors"
	"github.com/zitadel/zitadel/pkg/grpc/user/v2"
)

// Federated credentials of machine users (fork-only). The RPCs are "authenticated" in their auth
// option; the command and query layers check user.federated_credential.{read,write,delete} on the
// target user, which is also where every field is validated.

func (s *Server) AddFederatedCredential(ctx context.Context, req *connect.Request[user.AddFederatedCredentialRequest]) (*connect.Response[user.AddFederatedCredentialResponse], error) {
	credentialID, details, err := s.command.AddMachineFederatedCredential(ctx, req.Msg.GetUserId(), "", addFederatedCredentialRequestToDomain(req.Msg))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&user.AddFederatedCredentialResponse{
		CredentialId: credentialID,
		CreationDate: timestamppb.New(details.EventDate),
	}), nil
}

func (s *Server) UpdateFederatedCredential(ctx context.Context, req *connect.Request[user.UpdateFederatedCredentialRequest]) (*connect.Response[user.UpdateFederatedCredentialResponse], error) {
	details, err := s.command.ChangeMachineFederatedCredential(ctx, req.Msg.GetUserId(), req.Msg.GetCredentialId(), "", updateFederatedCredentialRequestToCommand(req.Msg))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&user.UpdateFederatedCredentialResponse{
		ChangeDate: timestamppb.New(details.EventDate),
	}), nil
}

func (s *Server) RemoveFederatedCredential(ctx context.Context, req *connect.Request[user.RemoveFederatedCredentialRequest]) (*connect.Response[user.RemoveFederatedCredentialResponse], error) {
	details, err := s.command.RemoveMachineFederatedCredential(ctx, req.Msg.GetUserId(), req.Msg.GetCredentialId(), "")
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&user.RemoveFederatedCredentialResponse{
		DeletionDate: timestamppb.New(details.EventDate),
	}), nil
}

func (s *Server) ListFederatedCredentials(ctx context.Context, req *connect.Request[user.ListFederatedCredentialsRequest]) (*connect.Response[user.ListFederatedCredentialsResponse], error) {
	if req.Msg.GetUserId() == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "USERv2-Fc1lst", "Errors.User.UserIDMissing")
	}
	offset, limit, asc, err := filter.PaginationPbToQuery(s.systemDefaults, req.Msg.GetPagination())
	if err != nil {
		return nil, err
	}
	userIDQuery, err := query.NewFederatedCredentialUserIDSearchQuery(req.Msg.GetUserId())
	if err != nil {
		return nil, err
	}
	search := &query.FederatedCredentialSearchQueries{
		SearchRequest: query.SearchRequest{
			Offset:        offset,
			Limit:         limit,
			Asc:           asc,
			SortingColumn: query.FederatedCredentialColumnCreationDate,
		},
		Queries: []query.SearchQuery{userIDQuery},
	}
	result, err := s.query.SearchFederatedCredentials(ctx, search, s.checkPermission)
	if err != nil {
		return nil, err
	}
	resp := &user.ListFederatedCredentialsResponse{
		Result:     make([]*user.FederatedCredential, len(result.FederatedCredentials)),
		Pagination: filter.QueryToPaginationPb(search.SearchRequest, result.SearchResponse),
	}
	for i, credential := range result.FederatedCredentials {
		resp.Result[i] = federatedCredentialToPb(credential)
	}
	return connect.NewResponse(resp), nil
}

func addFederatedCredentialRequestToDomain(req *user.AddFederatedCredentialRequest) *domain.FederatedCredential {
	keySource, pinnedKeys := federatedCredentialKeySourceToDomain(req.GetKeySource())
	return &domain.FederatedCredential{
		Issuer:           req.GetIssuer(),
		KeySource:        keySource,
		PinnedKeys:       pinnedKeys,
		Algorithms:       req.GetAllowedAlgorithms(),
		Audience:         req.GetAudience(),
		SubjectRule:      federatedCredentialSubjectRuleToDomain(req.GetSubjectRule()),
		ClaimConditions:  federatedCredentialClaimConditionsToDomain(req.GetClaimConditions()),
		MaxTokenAge:      req.GetMaxTokenAge().AsDuration(),
		MaxTokenLifetime: req.GetMaxTokenLifetime().AsDuration(),
		Disabled:         req.GetDisabled(),
	}
}

func updateFederatedCredentialRequestToCommand(req *user.UpdateFederatedCredentialRequest) *command.ChangeMachineFederatedCredential {
	change := &command.ChangeMachineFederatedCredential{
		Issuer:   req.Issuer,
		Audience: req.Audience,
		Disabled: req.Disabled,
	}
	if keySource := req.GetKeySource(); keySource != nil {
		source, pinnedKeys := federatedCredentialKeySourceToDomain(keySource)
		change.KeySource = &source
		change.PinnedKeys = pinnedKeys
	}
	if algorithms := req.GetAllowedAlgorithms(); len(algorithms) > 0 {
		change.Algorithms = algorithms
	}
	if rule := req.GetSubjectRule(); rule != nil {
		subjectRule := federatedCredentialSubjectRuleToDomain(rule)
		change.SubjectRule = &subjectRule
	}
	if conditions := req.GetClaimConditions(); conditions != nil {
		claimConditions := federatedCredentialClaimConditionsToDomain(conditions.GetConditions())
		if claimConditions == nil {
			claimConditions = []domain.FederatedCredentialClaimCondition{}
		}
		change.ClaimConditions = &claimConditions
	}
	if maxTokenAge := req.GetMaxTokenAge(); maxTokenAge != nil {
		age := maxTokenAge.AsDuration()
		change.MaxTokenAge = &age
	}
	if maxTokenLifetime := req.GetMaxTokenLifetime(); maxTokenLifetime != nil {
		lifetime := maxTokenLifetime.AsDuration()
		change.MaxTokenLifetime = &lifetime
	}
	return change
}

func federatedCredentialKeySourceToDomain(keySource *user.FederatedCredentialKeySource) (domain.FederatedCredentialKeySource, string) {
	switch source := keySource.GetSource().(type) {
	case *user.FederatedCredentialKeySource_IssuerMetadata:
		return domain.FederatedCredentialKeySourceIssuerMetadata, ""
	case *user.FederatedCredentialKeySource_PinnedKeys:
		return domain.FederatedCredentialKeySourcePinnedKeys, source.PinnedKeys.GetJwks()
	default:
		return domain.FederatedCredentialKeySourceUnspecified, ""
	}
}

func federatedCredentialSubjectRuleToDomain(rule *user.FederatedCredentialSubjectRule) domain.FederatedCredentialSubjectRule {
	return domain.FederatedCredentialSubjectRule{
		Claim:   rule.GetClaim(),
		Exact:   rule.GetExact(),
		Pattern: rule.GetPattern(),
	}
}

func federatedCredentialClaimConditionsToDomain(conditions []*user.FederatedCredentialClaimCondition) []domain.FederatedCredentialClaimCondition {
	if len(conditions) == 0 {
		return nil
	}
	converted := make([]domain.FederatedCredentialClaimCondition, len(conditions))
	for i, condition := range conditions {
		converted[i] = domain.FederatedCredentialClaimCondition{
			Claim: condition.GetClaim(),
			Value: condition.GetValue(),
		}
	}
	return converted
}

func federatedCredentialToPb(credential *query.FederatedCredential) *user.FederatedCredential {
	pb := &user.FederatedCredential{
		Id:                credential.ID,
		UserId:            credential.UserID,
		OrganizationId:    credential.ResourceOwner,
		CreationDate:      timestamppb.New(credential.CreationDate),
		ChangeDate:        timestamppb.New(credential.ChangeDate),
		Issuer:            credential.Issuer,
		KeySource:         federatedCredentialKeySourceToPb(credential.KeySource, credential.PinnedKeys),
		AllowedAlgorithms: credential.Algorithms,
		Audience:          credential.Audience,
		SubjectRule:       &user.FederatedCredentialSubjectRule{Claim: credential.SubjectRule.Claim},
		MaxTokenAge:       durationpb.New(credential.MaxTokenAge),
		MaxTokenLifetime:  durationpb.New(credential.MaxTokenLifetime),
		Disabled:          credential.Disabled,
	}
	if credential.SubjectRule.Pattern != "" {
		pb.SubjectRule.Match = &user.FederatedCredentialSubjectRule_Pattern{Pattern: credential.SubjectRule.Pattern}
	} else {
		pb.SubjectRule.Match = &user.FederatedCredentialSubjectRule_Exact{Exact: credential.SubjectRule.Exact}
	}
	if len(credential.ClaimConditions) > 0 {
		pb.ClaimConditions = make([]*user.FederatedCredentialClaimCondition, len(credential.ClaimConditions))
		for i, condition := range credential.ClaimConditions {
			pb.ClaimConditions[i] = &user.FederatedCredentialClaimCondition{Claim: condition.Claim, Value: condition.Value}
		}
	}
	return pb
}

func federatedCredentialKeySourceToPb(keySource domain.FederatedCredentialKeySource, pinnedKeys string) *user.FederatedCredentialKeySource {
	switch keySource {
	case domain.FederatedCredentialKeySourcePinnedKeys:
		return &user.FederatedCredentialKeySource{Source: &user.FederatedCredentialKeySource_PinnedKeys{
			PinnedKeys: &user.FederatedCredentialPinnedKeys{Jwks: pinnedKeys},
		}}
	case domain.FederatedCredentialKeySourceIssuerMetadata:
		return &user.FederatedCredentialKeySource{Source: &user.FederatedCredentialKeySource_IssuerMetadata{
			IssuerMetadata: &user.FederatedCredentialIssuerMetadataKeys{},
		}}
	case domain.FederatedCredentialKeySourceUnspecified:
		fallthrough
	default:
		return nil
	}
}
