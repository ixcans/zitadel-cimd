package settings

import (
	"context"

	"connectrpc.com/connect"

	"github.com/zitadel/zitadel/internal/api/grpc/object/v2"
	"github.com/zitadel/zitadel/pkg/grpc/settings/v2"
)

func (s *Server) SetSecuritySettings(ctx context.Context, req *connect.Request[settings.SetSecuritySettingsRequest]) (*connect.Response[settings.SetSecuritySettingsResponse], error) {
	details, err := s.command.SetSecurityPolicy(ctx, securitySettingsToCommand(req.Msg))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&settings.SetSecuritySettingsResponse{
		Details: object.DomainToDetailsPb(details),
	}), nil
}

func (s *Server) AddClientIDMetadataDocumentAllowedURL(ctx context.Context, req *connect.Request[settings.AddClientIDMetadataDocumentAllowedURLRequest]) (*connect.Response[settings.AddClientIDMetadataDocumentAllowedURLResponse], error) {
	details, err := s.command.AddClientIDMetadataDocumentAllowedURL(ctx, req.Msg.GetUrl())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&settings.AddClientIDMetadataDocumentAllowedURLResponse{
		CreationDate: timestamppb.New(details.EventDate),
	}), nil
}

func (s *Server) RemoveClientIDMetadataDocumentAllowedURL(ctx context.Context, req *connect.Request[settings.RemoveClientIDMetadataDocumentAllowedURLRequest]) (*connect.Response[settings.RemoveClientIDMetadataDocumentAllowedURLResponse], error) {
	details, err := s.command.RemoveClientIDMetadataDocumentAllowedURL(ctx, req.Msg.GetUrl())
	if err != nil {
		return nil, err
	}
	var deletionDate *timestamppb.Timestamp
	if details != nil {
		deletionDate = timestamppb.New(details.EventDate)
	}
	return connect.NewResponse(&settings.RemoveClientIDMetadataDocumentAllowedURLResponse{
		DeletionDate: deletionDate,
	}), nil
}

func (s *Server) SetHostedLoginTranslation(ctx context.Context, req *connect.Request[settings.SetHostedLoginTranslationRequest]) (*connect.Response[settings.SetHostedLoginTranslationResponse], error) {
	res, err := s.command.SetHostedLoginTranslation(ctx, req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(res), nil
}
