package settings

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/pkg/grpc/settings/v2"
)

func Test_securityPolicyToSettingsPb_clientIDMetadataDocumentAllowedAudiences(t *testing.T) {
	got := securityPolicyToSettingsPb(&query.SecurityPolicy{
		EnableClientIDMetadataDocument:           true,
		ClientIDMetadataDocumentAllowedURLs:      []string{"https://clients.example.com/"},
		ClientIDMetadataDocumentAllowedAudiences: []string{"123", "456"},
	})
	assert.Equal(t, &settings.ClientIDMetadataDocumentSettings{
		Enabled:                   true,
		AllowedUrls:               []string{"https://clients.example.com/"},
		AllowedAudienceProjectIds: []string{"123", "456"},
	}, got.GetClientIdMetadataDocument())
}

func Test_securitySettingsToCommand_clientIDMetadataDocumentAllowedAudiences(t *testing.T) {
	got := securitySettingsToCommand(&settings.SetSecuritySettingsRequest{
		ClientIdMetadataDocument: &settings.ClientIDMetadataDocumentSettings{
			Enabled:                   true,
			AllowedAudienceProjectIds: []string{"123", "456"},
		},
	})
	assert.True(t, got.EnableClientIDMetadataDocument)
	assert.Equal(t, []string{"123", "456"}, got.ClientIDMetadataDocumentAllowedAudiences)
}

// The set call replaces every setting: a request that omits the list, or the whole client ID
// metadata document message, yields an empty list, which clears it.
func Test_securitySettingsToCommand_clientIDMetadataDocumentAllowedAudiencesOmitted(t *testing.T) {
	got := securitySettingsToCommand(&settings.SetSecuritySettingsRequest{
		ClientIdMetadataDocument: &settings.ClientIDMetadataDocumentSettings{Enabled: true},
	})
	assert.Empty(t, got.ClientIDMetadataDocumentAllowedAudiences)

	got = securitySettingsToCommand(&settings.SetSecuritySettingsRequest{})
	assert.Empty(t, got.ClientIDMetadataDocumentAllowedAudiences)
}
