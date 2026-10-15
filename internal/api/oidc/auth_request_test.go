package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

func TestBuildLoginV2LogoutURL(t *testing.T) {
	t.Parallel()

	tt := []struct {
		testName       string
		logoutURIStr   string
		redirectURI    string
		logoutHint     string
		uiLocales      []language.Tag
		signer         jose.Signer
		expectedParams map[string]string
	}{
		{
			testName:     "basic with only redirectURI",
			logoutURIStr: "https://example.com/logout",
			redirectURI:  "https://client/cb",
			expectedParams: map[string]string{
				"post_logout_redirect": "https://client/cb",
				"logout_token":         "", // presence checked separately
			},
		},
		{
			testName:     "with logout hint",
			logoutURIStr: "https://example.com/logout",
			redirectURI:  "https://client/cb",
			logoutHint:   "user@example.com",
			expectedParams: map[string]string{
				"post_logout_redirect": "https://client/cb",
				"logout_hint":          "user@example.com",
				"logout_token":         "", // presence checked separately
			},
		},
		{
			testName:     "with ui_locales",
			logoutURIStr: "https://example.com/logout",
			redirectURI:  "https://client/cb",
			uiLocales:    []language.Tag{language.English, language.Italian},
			expectedParams: map[string]string{
				"post_logout_redirect": "https://client/cb",
				"ui_locales":           "en it",
				"logout_token":         "", // presence checked separately
			},
		},
		{
			testName:     "with all params",
			logoutURIStr: "https://example.com/logout",
			redirectURI:  "https://client/cb",
			logoutHint:   "logoutme",
			uiLocales:    []language.Tag{language.Make("de-CH"), language.Make("fr")},
			expectedParams: map[string]string{
				"post_logout_redirect": "https://client/cb",
				"logout_hint":          "logoutme",
				"ui_locales":           "de-CH fr",
				"logout_token":         "", // presence checked separately
			},
		},
		{
			testName:     "base with trailing slash",
			logoutURIStr: "https://example.com/logout/",
			redirectURI:  "https://client/cb",
			expectedParams: map[string]string{
				"post_logout_redirect": "https://client/cb",
				"logout_token":         "", // presence checked separately
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.testName, func(t *testing.T) {
			// t.Parallel()

			// Given
			logoutURI, err := url.Parse(tc.logoutURIStr)
			require.NoError(t, err)

			// When
			got, err := buildLoginV2LogoutURL(logoutURI, tc.redirectURI, tc.logoutHint, tc.uiLocales, signer)

			// Then
			require.NoError(t, err)
			gotURL, err := url.Parse(got)
			require.NoError(t, err)
			require.NotContains(t, gotURL.String(), "/logout/")

			q := gotURL.Query()
			// Ensure no unexpected params
			require.Len(t, q, len(tc.expectedParams))

			for k, v := range tc.expectedParams {
				if k == LoginLogoutTokenParam {
					assertLogoutToken(t, q.Get(k), &logoutTokenPayload{
						PostLogoutRedirectURI: tc.redirectURI,
						LogoutHint:            tc.logoutHint,
						UILocales:             tc.uiLocales,
					})
					continue
				}
				assert.Equal(t, v, q.Get(k))
			}
		})
	}
}

func assertLogoutToken(t *testing.T, token string, payload *logoutTokenPayload) {
	signature, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	logoutToken := new(logoutTokenPayload)
	err = json.Unmarshal(signature.UnsafePayloadWithoutVerification(), logoutToken)
	require.NoError(t, err)
	assert.Equal(t, payload, logoutToken)
}

var (
	privKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	signer     = func() jose.Signer {
		signer, _ := jose.NewSigner(
			jose.SigningKey{
				Algorithm: jose.RS256,
				Key:       privKey,
			},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		return signer
	}()
)

func TestV2LogoutDoneRedirect(t *testing.T) {
	t.Parallel()

	mustParse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		return u
	}

	tt := []struct {
		testName           string
		redirectURI        string
		baseURI            *url.URL
		defaultLogoutURLV2 string
		want               string
	}{
		{
			testName:           "a client's own post_logout_redirect_uri is kept",
			redirectURI:        "https://client.example.com/signed-out",
			baseURI:            mustParse("https://login.example.com/ui/v2/login"),
			defaultLogoutURLV2: "/ui/v2/login/logout?post_logout_redirect=",
			want:               "https://client.example.com/signed-out",
		},
		{
			testName:           "no redirect: the done page under the instance's login base URI",
			redirectURI:        "/ui/login/logout/done",
			baseURI:            mustParse("https://login.example.com/ui/v2/login"),
			defaultLogoutURLV2: "/ui/v2/login/logout?post_logout_redirect=",
			want:               "https://login.example.com/ui/v2/login/logout/done",
		},
		{
			testName:           "no redirect and no base URI: the done page under the default logout URL's base",
			redirectURI:        "/ui/login/logout/done",
			defaultLogoutURLV2: "/ui/v2/login/logout?post_logout_redirect=",
			want:               "/ui/v2/login/logout/done",
		},
		{
			testName:           "an absolute default logout URL keeps its host",
			redirectURI:        "/ui/login/logout/done",
			baseURI:            &url.URL{},
			defaultLogoutURLV2: "https://login.example.com/custom/logout?post_logout_redirect=#x",
			want:               "https://login.example.com/custom/logout/done",
		},
		{
			testName:           "a login UI served at the root keeps the bare path",
			redirectURI:        "/ui/login/logout/done",
			defaultLogoutURLV2: "/logout?post_logout_redirect=",
			want:               "/logout/done",
		},
		{
			testName:           "a default logout URL not ending in the logout path falls back to the bare path",
			redirectURI:        "/ui/login/logout/done",
			defaultLogoutURLV2: "/somewhere/else",
			want:               "/logout/done",
		},
	}

	for _, tc := range tt {
		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, v2LogoutDoneRedirect(tc.redirectURI, tc.baseURI, tc.defaultLogoutURLV2))
		})
	}
}
