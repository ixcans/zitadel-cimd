package command

import (
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/user"
)

// MachineFederatedCredentialWriteModel is one federated credential of a user, together with the
// user's type and existence, which decide whether the credential may be managed at all.
type MachineFederatedCredentialWriteModel struct {
	eventstore.WriteModel

	CredentialID string
	UserType     domain.UserType
	// Credential is the current configuration, nil when the credential does not exist.
	Credential *domain.FederatedCredential
}

func NewMachineFederatedCredentialWriteModel(userID, credentialID, resourceOwner string) *MachineFederatedCredentialWriteModel {
	return &MachineFederatedCredentialWriteModel{
		WriteModel: eventstore.WriteModel{
			AggregateID:   userID,
			ResourceOwner: resourceOwner,
		},
		CredentialID: credentialID,
	}
}

func (wm *MachineFederatedCredentialWriteModel) GetWriteModel() *eventstore.WriteModel {
	return &wm.WriteModel
}

func (wm *MachineFederatedCredentialWriteModel) AppendEvents(events ...eventstore.Event) {
	for _, event := range events {
		switch e := event.(type) {
		case *user.MachineFederatedCredentialAddedEvent:
			if e.CredentialID != wm.CredentialID {
				continue
			}
		case *user.MachineFederatedCredentialChangedEvent:
			if e.CredentialID != wm.CredentialID {
				continue
			}
		case *user.MachineFederatedCredentialRemovedEvent:
			if e.CredentialID != wm.CredentialID {
				continue
			}
		}
		wm.WriteModel.AppendEvents(event)
	}
}

func (wm *MachineFederatedCredentialWriteModel) Reduce() error {
	for _, event := range wm.Events {
		switch e := event.(type) {
		case *user.HumanAddedEvent, *user.HumanRegisteredEvent:
			wm.UserType = domain.UserTypeHuman
		case *user.MachineAddedEvent:
			wm.UserType = domain.UserTypeMachine
		case *user.UserRemovedEvent:
			wm.UserType = domain.UserTypeUnspecified
			wm.Credential = nil
		case *user.MachineFederatedCredentialAddedEvent:
			wm.Credential = e.Credential()
		case *user.MachineFederatedCredentialChangedEvent:
			if wm.Credential != nil {
				e.Apply(wm.Credential)
			}
		case *user.MachineFederatedCredentialRemovedEvent:
			wm.Credential = nil
		}
	}
	return wm.WriteModel.Reduce()
}

func (wm *MachineFederatedCredentialWriteModel) Query() *eventstore.SearchQueryBuilder {
	return eventstore.NewSearchQueryBuilder(eventstore.ColumnsEvent).
		ResourceOwner(wm.ResourceOwner).
		AddQuery().
		AggregateTypes(user.AggregateType).
		AggregateIDs(wm.AggregateID).
		EventTypes(
			user.UserV1AddedType,
			user.UserV1RegisteredType,
			user.HumanAddedType,
			user.HumanRegisteredType,
			user.MachineAddedEventType,
			user.UserRemovedType,
			user.MachineFederatedCredentialAddedEventType,
			user.MachineFederatedCredentialChangedEventType,
			user.MachineFederatedCredentialRemovedEventType,
		).
		Builder()
}

// UserExists reports whether the user exists, of either type.
func (wm *MachineFederatedCredentialWriteModel) UserExists() bool {
	return wm.UserType != domain.UserTypeUnspecified
}

// Exists reports whether the credential exists.
func (wm *MachineFederatedCredentialWriteModel) Exists() bool {
	return wm.Credential != nil
}
