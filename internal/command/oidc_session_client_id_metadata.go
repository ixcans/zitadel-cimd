package command

import (
	"github.com/zitadel/zitadel/internal/domain"
)

// sessionOwnedByMetadataDocumentClient reports whether clientID is a Client ID Metadata Document
// client and the client the OIDC session was created for, so that it may act on the session's
// tokens as their client, for example revoke them (RFC 7009).
//
// For any other client, the session check asks whether the client is in the session's audience,
// which for a registered application lists the client IDs of its project. A client resolved from a
// metadata document belongs to no project: its session audience holds only the projects it was
// granted as an audience, or nothing, and never the client itself. The client is recorded as the
// session's own client, which is also how the code exchange and the refresh grant identify it.
// Registered and dynamically registered clients are not affected: their client IDs are generated
// and never such a URL.
func sessionOwnedByMetadataDocumentClient(sessionClientID, clientID string) bool {
	return domain.IsClientIDMetadataDocumentURL(clientID) && sessionClientID == clientID
}
