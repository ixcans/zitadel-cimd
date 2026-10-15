package settings

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zitadel/zitadel/pkg/grpc/settings/v2"
)

func (s *Server) AddClientIDMetadataDocumentAllowedAudience(ctx context.Context, req *connect.Request[settings.AddClientIDMetadataDocumentAllowedAudienceRequest]) (*connect.Response[settings.AddClientIDMetadataDocumentAllowedAudienceResponse], error) {
	details, err := s.command.AddClientIDMetadataDocumentAllowedAudience(ctx, req.Msg.GetProjectId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&settings.AddClientIDMetadataDocumentAllowedAudienceResponse{
		CreationDate: timestamppb.New(details.EventDate),
	}), nil
}

func (s *Server) RemoveClientIDMetadataDocumentAllowedAudience(ctx context.Context, req *connect.Request[settings.RemoveClientIDMetadataDocumentAllowedAudienceRequest]) (*connect.Response[settings.RemoveClientIDMetadataDocumentAllowedAudienceResponse], error) {
	details, err := s.command.RemoveClientIDMetadataDocumentAllowedAudience(ctx, req.Msg.GetProjectId())
	if err != nil {
		return nil, err
	}
	var deletionDate *timestamppb.Timestamp
	if details != nil {
		deletionDate = timestamppb.New(details.EventDate)
	}
	return connect.NewResponse(&settings.RemoveClientIDMetadataDocumentAllowedAudienceResponse{
		DeletionDate: deletionDate,
	}), nil
}
