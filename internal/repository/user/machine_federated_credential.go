package user

import (
	"context"
	"slices"
	"time"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
)

// Federated credentials of machine users (see domain.FederatedCredential) are not part of upstream
// ZITADEL. Their event types carry the fork-local "_ixcans_fork" suffix: these events are durable
// history, and a later upstream feature under a plain name must never reinterpret them. Stock code
// has no mapper for these types, so it ignores them instead of reading them with other semantics.
const (
	machineFederatedCredentialEventPrefix      = machineEventPrefix + "federated_credential_ixcans_fork."
	MachineFederatedCredentialAddedEventType   = machineFederatedCredentialEventPrefix + "added"
	MachineFederatedCredentialChangedEventType = machineFederatedCredentialEventPrefix + "changed"
	MachineFederatedCredentialRemovedEventType = machineFederatedCredentialEventPrefix + "removed"
)

func init() {
	eventstore.RegisterFilterEventMapper(AggregateType, MachineFederatedCredentialAddedEventType, eventstore.GenericEventMapper[MachineFederatedCredentialAddedEvent])
	eventstore.RegisterFilterEventMapper(AggregateType, MachineFederatedCredentialChangedEventType, eventstore.GenericEventMapper[MachineFederatedCredentialChangedEvent])
	eventstore.RegisterFilterEventMapper(AggregateType, MachineFederatedCredentialRemovedEventType, eventstore.GenericEventMapper[MachineFederatedCredentialRemovedEvent])
}

// MachineFederatedCredentialAddedEvent records the whole configuration of a new credential.
type MachineFederatedCredentialAddedEvent struct {
	eventstore.BaseEvent `json:"-"`

	CredentialID     string                                     `json:"credentialId"`
	Issuer           string                                     `json:"issuer"`
	KeySource        domain.FederatedCredentialKeySource        `json:"keySource"`
	PinnedKeys       string                                     `json:"pinnedKeys,omitempty"`
	Algorithms       []string                                   `json:"algorithms"`
	Audience         string                                     `json:"audience"`
	SubjectRule      domain.FederatedCredentialSubjectRule      `json:"subjectRule"`
	ClaimConditions  []domain.FederatedCredentialClaimCondition `json:"claimConditions,omitempty"`
	MaxTokenAge      time.Duration                              `json:"maxTokenAge"`
	MaxTokenLifetime time.Duration                              `json:"maxTokenLifetime"`
	Disabled         bool                                       `json:"disabled,omitempty"`
}

func (e *MachineFederatedCredentialAddedEvent) SetBaseEvent(event *eventstore.BaseEvent) {
	e.BaseEvent = *event
}

func (e *MachineFederatedCredentialAddedEvent) Payload() interface{} {
	return e
}

func (e *MachineFederatedCredentialAddedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

// Credential returns the configuration the event records.
func (e *MachineFederatedCredentialAddedEvent) Credential() *domain.FederatedCredential {
	return &domain.FederatedCredential{
		Issuer:           e.Issuer,
		KeySource:        e.KeySource,
		PinnedKeys:       e.PinnedKeys,
		Algorithms:       e.Algorithms,
		Audience:         e.Audience,
		SubjectRule:      e.SubjectRule,
		ClaimConditions:  e.ClaimConditions,
		MaxTokenAge:      e.MaxTokenAge,
		MaxTokenLifetime: e.MaxTokenLifetime,
		Disabled:         e.Disabled,
	}
}

func NewMachineFederatedCredentialAddedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	credentialID string,
	credential *domain.FederatedCredential,
) *MachineFederatedCredentialAddedEvent {
	return &MachineFederatedCredentialAddedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			MachineFederatedCredentialAddedEventType,
		),
		CredentialID:     credentialID,
		Issuer:           credential.Issuer,
		KeySource:        credential.KeySource,
		PinnedKeys:       credential.PinnedKeys,
		Algorithms:       credential.Algorithms,
		Audience:         credential.Audience,
		SubjectRule:      credential.SubjectRule,
		ClaimConditions:  credential.ClaimConditions,
		MaxTokenAge:      credential.MaxTokenAge,
		MaxTokenLifetime: credential.MaxTokenLifetime,
		Disabled:         credential.Disabled,
	}
}

// MachineFederatedCredentialChangedEvent records the fields of a credential that changed; a nil
// field did not change. Disabling and enabling a credential are changes of Disabled.
type MachineFederatedCredentialChangedEvent struct {
	eventstore.BaseEvent `json:"-"`

	CredentialID     string                                      `json:"credentialId"`
	Issuer           *string                                     `json:"issuer,omitempty"`
	KeySource        *domain.FederatedCredentialKeySource        `json:"keySource,omitempty"`
	PinnedKeys       *string                                     `json:"pinnedKeys,omitempty"`
	Algorithms       *[]string                                   `json:"algorithms,omitempty"`
	Audience         *string                                     `json:"audience,omitempty"`
	SubjectRule      *domain.FederatedCredentialSubjectRule      `json:"subjectRule,omitempty"`
	ClaimConditions  *[]domain.FederatedCredentialClaimCondition `json:"claimConditions,omitempty"`
	MaxTokenAge      *time.Duration                              `json:"maxTokenAge,omitempty"`
	MaxTokenLifetime *time.Duration                              `json:"maxTokenLifetime,omitempty"`
	Disabled         *bool                                       `json:"disabled,omitempty"`
}

func (e *MachineFederatedCredentialChangedEvent) SetBaseEvent(event *eventstore.BaseEvent) {
	e.BaseEvent = *event
}

func (e *MachineFederatedCredentialChangedEvent) Payload() interface{} {
	return e
}

func (e *MachineFederatedCredentialChangedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

// Apply writes the changed fields into credential.
func (e *MachineFederatedCredentialChangedEvent) Apply(credential *domain.FederatedCredential) {
	if e.Issuer != nil {
		credential.Issuer = *e.Issuer
	}
	if e.KeySource != nil {
		credential.KeySource = *e.KeySource
	}
	if e.PinnedKeys != nil {
		credential.PinnedKeys = *e.PinnedKeys
	}
	if e.Algorithms != nil {
		credential.Algorithms = *e.Algorithms
	}
	if e.Audience != nil {
		credential.Audience = *e.Audience
	}
	if e.SubjectRule != nil {
		credential.SubjectRule = *e.SubjectRule
	}
	if e.ClaimConditions != nil {
		credential.ClaimConditions = *e.ClaimConditions
	}
	if e.MaxTokenAge != nil {
		credential.MaxTokenAge = *e.MaxTokenAge
	}
	if e.MaxTokenLifetime != nil {
		credential.MaxTokenLifetime = *e.MaxTokenLifetime
	}
	if e.Disabled != nil {
		credential.Disabled = *e.Disabled
	}
}

// NewMachineFederatedCredentialChangedEvent returns the event for the fields that differ between
// before and after, or nil when nothing differs.
func NewMachineFederatedCredentialChangedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	credentialID string,
	before, after *domain.FederatedCredential,
) *MachineFederatedCredentialChangedEvent {
	e := &MachineFederatedCredentialChangedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			MachineFederatedCredentialChangedEventType,
		),
		CredentialID: credentialID,
	}
	changed := false
	if before.Issuer != after.Issuer {
		e.Issuer, changed = &after.Issuer, true
	}
	if before.KeySource != after.KeySource {
		e.KeySource, changed = &after.KeySource, true
	}
	if before.PinnedKeys != after.PinnedKeys {
		e.PinnedKeys, changed = &after.PinnedKeys, true
	}
	if !slices.Equal(before.Algorithms, after.Algorithms) {
		algorithms := append([]string{}, after.Algorithms...)
		e.Algorithms, changed = &algorithms, true
	}
	if before.Audience != after.Audience {
		e.Audience, changed = &after.Audience, true
	}
	if before.SubjectRule != after.SubjectRule {
		e.SubjectRule, changed = &after.SubjectRule, true
	}
	if !slices.Equal(before.ClaimConditions, after.ClaimConditions) {
		conditions := append([]domain.FederatedCredentialClaimCondition{}, after.ClaimConditions...)
		e.ClaimConditions, changed = &conditions, true
	}
	if before.MaxTokenAge != after.MaxTokenAge {
		e.MaxTokenAge, changed = &after.MaxTokenAge, true
	}
	if before.MaxTokenLifetime != after.MaxTokenLifetime {
		e.MaxTokenLifetime, changed = &after.MaxTokenLifetime, true
	}
	if before.Disabled != after.Disabled {
		e.Disabled, changed = &after.Disabled, true
	}
	if !changed {
		return nil
	}
	return e
}

// MachineFederatedCredentialRemovedEvent records that a credential was deleted.
type MachineFederatedCredentialRemovedEvent struct {
	eventstore.BaseEvent `json:"-"`

	CredentialID string `json:"credentialId"`
}

func (e *MachineFederatedCredentialRemovedEvent) SetBaseEvent(event *eventstore.BaseEvent) {
	e.BaseEvent = *event
}

func (e *MachineFederatedCredentialRemovedEvent) Payload() interface{} {
	return e
}

func (e *MachineFederatedCredentialRemovedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewMachineFederatedCredentialRemovedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	credentialID string,
) *MachineFederatedCredentialRemovedEvent {
	return &MachineFederatedCredentialRemovedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			MachineFederatedCredentialRemovedEventType,
		),
		CredentialID: credentialID,
	}
}
