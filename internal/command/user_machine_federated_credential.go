package command

import (
	"context"
	"slices"
	"time"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/repository/user"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// ChangeMachineFederatedCredential holds the changes to a federated credential; a nil field stays
// as it is. PinnedKeys is applied only together with KeySource (empty for the issuer's metadata).
type ChangeMachineFederatedCredential struct {
	Issuer           *string
	KeySource        *domain.FederatedCredentialKeySource
	PinnedKeys       string
	Algorithms       []string
	Audience         *string
	SubjectRule      *domain.FederatedCredentialSubjectRule
	ClaimConditions  *[]domain.FederatedCredentialClaimCondition
	MaxTokenAge      *time.Duration
	MaxTokenLifetime *time.Duration
	Disabled         *bool
}

func (ch *ChangeMachineFederatedCredential) apply(credential *domain.FederatedCredential) *domain.FederatedCredential {
	changed := *credential
	changed.Algorithms = slices.Clone(credential.Algorithms)
	changed.ClaimConditions = slices.Clone(credential.ClaimConditions)
	if ch.Issuer != nil {
		changed.Issuer = *ch.Issuer
	}
	if ch.KeySource != nil {
		changed.KeySource = *ch.KeySource
		changed.PinnedKeys = ch.PinnedKeys
	}
	if ch.Algorithms != nil {
		changed.Algorithms = slices.Clone(ch.Algorithms)
	}
	if ch.Audience != nil {
		changed.Audience = *ch.Audience
	}
	if ch.SubjectRule != nil {
		changed.SubjectRule = *ch.SubjectRule
	}
	if ch.ClaimConditions != nil {
		changed.ClaimConditions = slices.Clone(*ch.ClaimConditions)
	}
	if ch.MaxTokenAge != nil {
		changed.MaxTokenAge = *ch.MaxTokenAge
	}
	if ch.MaxTokenLifetime != nil {
		changed.MaxTokenLifetime = *ch.MaxTokenLifetime
	}
	if ch.Disabled != nil {
		changed.Disabled = *ch.Disabled
	}
	return &changed
}

// AddMachineFederatedCredential attaches a federated credential to a machine user and returns the
// new credential's ID. The caller needs user.federated_credential.write on the user; a user cannot
// add one to itself, and a human user cannot hold one.
func (c *Commands) AddMachineFederatedCredential(ctx context.Context, userID, resourceOwner string, credential *domain.FederatedCredential) (_ string, _ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if userID == "" {
		return "", nil, zerrors.ThrowInvalidArgument(nil, "COMMAND-Fc1add", "Errors.User.UserIDMissing")
	}
	if credential == nil {
		return "", nil, zerrors.ThrowInvalidArgument(nil, "COMMAND-Fc2add", "Errors.Internal")
	}
	if err := credential.Validate(); err != nil {
		return "", nil, err
	}
	credentialID, err := c.idGenerator.Next()
	if err != nil {
		return "", nil, err
	}
	wm, err := c.machineFederatedCredentialWriteModel(ctx, userID, credentialID, resourceOwner, domain.PermissionUserFederatedCredentialWrite)
	if err != nil {
		return "", nil, err
	}
	if wm.UserType != domain.UserTypeMachine {
		return "", nil, zerrors.ThrowPreconditionFailed(nil, "COMMAND-Fc3add", "Errors.User.NotMachine")
	}
	if wm.Exists() {
		return "", nil, zerrors.ThrowAlreadyExists(nil, "COMMAND-Fc4add", "Errors.User.Machine.FederatedCredential.AlreadyExists")
	}
	details, err := c.pushAppendAndReduceDetails(ctx, wm, user.NewMachineFederatedCredentialAddedEvent(
		ctx,
		UserAggregateFromWriteModelCtx(ctx, &wm.WriteModel),
		credentialID,
		credential,
	))
	if err != nil {
		return "", nil, err
	}
	return credentialID, details, nil
}

// ChangeMachineFederatedCredential changes a federated credential, including disabling and enabling
// it. The changed configuration is validated as a whole. Without any change no event is written.
func (c *Commands) ChangeMachineFederatedCredential(ctx context.Context, userID, credentialID, resourceOwner string, change *ChangeMachineFederatedCredential) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if err := validateMachineFederatedCredentialIDs(userID, credentialID); err != nil {
		return nil, err
	}
	wm, err := c.machineFederatedCredentialWriteModel(ctx, userID, credentialID, resourceOwner, domain.PermissionUserFederatedCredentialWrite)
	if err != nil {
		return nil, err
	}
	if !wm.Exists() {
		return nil, zerrors.ThrowNotFound(nil, "COMMAND-Fc1chg", "Errors.User.Machine.FederatedCredential.NotFound")
	}
	if change == nil {
		return writeModelToObjectDetails(&wm.WriteModel), nil
	}
	changed := change.apply(wm.Credential)
	if err := changed.Validate(); err != nil {
		return nil, err
	}
	event := user.NewMachineFederatedCredentialChangedEvent(
		ctx,
		UserAggregateFromWriteModelCtx(ctx, &wm.WriteModel),
		credentialID,
		wm.Credential,
		changed,
	)
	if event == nil {
		return writeModelToObjectDetails(&wm.WriteModel), nil
	}
	return c.pushAppendAndReduceDetails(ctx, wm, event)
}

// RemoveMachineFederatedCredential deletes a federated credential. The caller needs
// user.federated_credential.delete on the user.
func (c *Commands) RemoveMachineFederatedCredential(ctx context.Context, userID, credentialID, resourceOwner string) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if err := validateMachineFederatedCredentialIDs(userID, credentialID); err != nil {
		return nil, err
	}
	wm, err := c.machineFederatedCredentialWriteModel(ctx, userID, credentialID, resourceOwner, domain.PermissionUserFederatedCredentialDelete)
	if err != nil {
		return nil, err
	}
	if !wm.Exists() {
		return nil, zerrors.ThrowNotFound(nil, "COMMAND-Fc1rmv", "Errors.User.Machine.FederatedCredential.NotFound")
	}
	return c.pushAppendAndReduceDetails(ctx, wm, user.NewMachineFederatedCredentialRemovedEvent(
		ctx,
		UserAggregateFromWriteModelCtx(ctx, &wm.WriteModel),
		credentialID,
	))
}

func validateMachineFederatedCredentialIDs(userID, credentialID string) error {
	if userID == "" {
		return zerrors.ThrowInvalidArgument(nil, "COMMAND-Fc1ids", "Errors.User.UserIDMissing")
	}
	if credentialID == "" {
		return zerrors.ThrowInvalidArgument(nil, "COMMAND-Fc2ids", "Errors.IDMissing")
	}
	return nil
}

// machineFederatedCredentialWriteModel loads the credential and checks that the user exists and
// that the caller holds permission on it. Self-management is not allowed: a machine user that could
// add a federated credential to itself could hand its identity to any issuer.
func (c *Commands) machineFederatedCredentialWriteModel(ctx context.Context, userID, credentialID, resourceOwner, permission string) (*MachineFederatedCredentialWriteModel, error) {
	wm := NewMachineFederatedCredentialWriteModel(userID, credentialID, resourceOwner)
	if err := c.eventstore.FilterToQueryReducer(ctx, wm); err != nil {
		return nil, err
	}
	if !wm.UserExists() {
		return nil, zerrors.ThrowNotFound(nil, "COMMAND-Fc1wmd", "Errors.User.NotFound")
	}
	if err := c.checkPermissionOnUser(ctx, permission, false)(wm.ResourceOwner, wm.AggregateID); err != nil {
		return nil, err
	}
	return wm, nil
}
