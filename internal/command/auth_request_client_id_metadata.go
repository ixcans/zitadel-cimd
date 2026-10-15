package command

import (
	"github.com/zitadel/zitadel/internal/domain"
)

// authRequestClientHasProject reports whether the client of an auth request belongs to a project,
// so that linking a session to the request must run the project permission check (the project's
// "check for project on authentication" and "check authorization on authentication" settings).
//
// A client identified by a Client ID Metadata Document URL belongs to no project: it is described
// by a document anyone can publish, not registered as an application, so there is no project whose
// settings could apply and no application row the check could look up. Whether such a client may
// start an auth request at all was already decided by the instance's settings when the request was
// created. Registered applications, dynamically registered ones included, get generated client IDs,
// which are never such a URL, so every one of them is still checked.
func authRequestClientHasProject(clientID string) bool {
	return !domain.IsClientIDMetadataDocumentURL(clientID)
}
