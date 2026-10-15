package oidc

import (
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// checkDeviceAuthorizationGrant refuses to start a device authorization for a client that may not
// use the device code grant. The protocol layer's legacy handler makes this check before it starts
// one; its server handler, which this package is served through, does not, so a client that could
// never redeem the device code could otherwise still have a user code issued and shown to a user.
//
// A client resolved from a Client ID Metadata Document never holds the device code grant
// (client_metadata_tokens.go), so for such a client this check and the token endpoint's grant check
// are the whole guard against the device flow.
func checkDeviceAuthorizationGrant(client op.Client) error {
	if op.ValidateGrantType(client, oidc.GrantTypeDeviceCode) {
		return nil
	}
	return oidc.ErrUnauthorizedClient().WithDescription("client missing grant type " + string(oidc.GrantTypeDeviceCode))
}
