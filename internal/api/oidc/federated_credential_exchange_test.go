package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/publicfetch"
	"github.com/zitadel/zitadel/internal/query"
)

// testIssuerKey is a signing key of the in-process issuer.
type testIssuerKey struct {
	kid     string
	alg     jose.SignatureAlgorithm
	private crypto.Signer
}

func newTestIssuerKey(t *testing.T, kid string, alg jose.SignatureAlgorithm) *testIssuerKey {
	t.Helper()
	var (
		private crypto.Signer
		err     error
	)
	switch alg {
	case jose.ES256:
		private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.RS256:
		private, err = rsa.GenerateKey(rand.Reader, 2048)
	case jose.EdDSA:
		_, private, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unsupported algorithm %s", alg)
	}
	require.NoError(t, err)
	return &testIssuerKey{kid: kid, alg: alg, private: private}
}

func (k *testIssuerKey) publicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.private.Public(), KeyID: k.kid, Use: "sig", Algorithm: string(k.alg)}
}

func (k *testIssuerKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: k.alg, Key: jose.JSONWebKey{Key: k.private, KeyID: k.kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	signed, err := signer.Sign(payload)
	require.NoError(t, err)
	compact, err := signed.CompactSerialize()
	require.NoError(t, err)
	return compact
}

// testIssuer is an in-process OpenID Provider that serves its metadata and its key set, like a
// workload platform does.
type testIssuer struct {
	server       *httptest.Server
	metadataHits atomic.Int32
	keyHits      atomic.Int32

	mu             sync.Mutex
	keys           []jose.JSONWebKey
	metadataIssuer string
	fail           bool
}

func newTestIssuer(t *testing.T, keys ...*testIssuerKey) *testIssuer {
	t.Helper()
	issuer := new(testIssuer)
	for _, key := range keys {
		issuer.keys = append(issuer.keys, key.publicJWK())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer.metadataHits.Add(1)
		issuer.mu.Lock()
		defer issuer.mu.Unlock()
		if issuer.fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		name := issuer.metadataIssuer
		if name == "" {
			name = issuer.server.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": name, "jwks_uri": issuer.server.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		issuer.keyHits.Add(1)
		issuer.mu.Lock()
		defer issuer.mu.Unlock()
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: issuer.keys})
	})
	issuer.server = httptest.NewTLSServer(mux)
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *testIssuer) setKeys(keys ...*testIssuerKey) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = nil
	for _, key := range keys {
		i.keys = append(i.keys, key.publicJWK())
	}
}

func (i *testIssuer) setFail(fail bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.fail = fail
}

// testClock is the time of the exchanger and of its key cache.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testCredentialStore stands in for the read model: it returns the enabled credentials whose issuer
// equals the token's exactly, as the query does, and counts the lookups.
type testCredentialStore struct {
	credentials []*query.FederatedCredential
	lookups     atomic.Int32
	// raw returns every credential whatever its issuer or state, to check that the exchange does
	// not rely on the read model alone.
	raw bool
}

func (s *testCredentialStore) lookup(_ context.Context, issuer string) ([]*query.FederatedCredential, error) {
	s.lookups.Add(1)
	if s.raw {
		return s.credentials, nil
	}
	var found []*query.FederatedCredential
	for _, credential := range s.credentials {
		if credential.Issuer == issuer && !credential.Disabled {
			found = append(found, credential)
		}
	}
	return found, nil
}

type exchangeFixture struct {
	issuer *testIssuer
	key    *testIssuerKey
	clock  *testClock
	store  *testCredentialStore
	keys   *federatedIssuerKeys
	ex     *federatedCredentialExchanger
}

func newExchangeFixture(t *testing.T, alg jose.SignatureAlgorithm, credentials ...func(issuer string) *query.FederatedCredential) *exchangeFixture {
	t.Helper()
	key := newTestIssuerKey(t, "key1", alg)
	issuer := newTestIssuer(t, key)
	clock := &testClock{now: time.Unix(1_800_000_000, 0)}
	store := new(testCredentialStore)
	for _, credential := range credentials {
		store.credentials = append(store.credentials, credential(issuer.server.URL))
	}
	keys := newFederatedIssuerKeys(issuer.server.Client())
	keys.now = clock.Now
	ex := newFederatedCredentialExchanger(store.lookup, keys)
	ex.now = clock.Now
	return &exchangeFixture{issuer: issuer, key: key, clock: clock, store: store, keys: keys, ex: ex}
}

// testCredential is a credential of machine1 for the workload "repo:example/app" that accepts all
// three algorithms, with the token's age limited to five minutes and the machine token to ten.
func testCredential(modify ...func(*query.FederatedCredential)) func(issuer string) *query.FederatedCredential {
	return func(issuer string) *query.FederatedCredential {
		credential := &query.FederatedCredential{
			ID:            "cred1",
			UserID:        "machine1",
			ResourceOwner: "org1",
			FederatedCredential: domain.FederatedCredential{
				Issuer:           issuer,
				KeySource:        domain.FederatedCredentialKeySourceIssuerMetadata,
				Algorithms:       []string{"ES256", "RS256", "EdDSA"},
				Audience:         "https://login.example.com",
				SubjectRule:      domain.FederatedCredentialSubjectRule{Claim: "sub", Exact: "repo:example/app"},
				ClaimConditions:  []domain.FederatedCredentialClaimCondition{{Claim: "environment", Value: "prod"}},
				MaxTokenAge:      5 * time.Minute,
				MaxTokenLifetime: 10 * time.Minute,
			},
		}
		for _, m := range modify {
			m(credential)
		}
		return credential
	}
}

// claims are those of a valid token for testCredential, issued a minute before the clock's time.
func (f *exchangeFixture) claims(modify ...func(map[string]any)) map[string]any {
	now := f.clock.Now()
	claims := map[string]any{
		"iss":         f.issuer.server.URL,
		"sub":         "repo:example/app",
		"aud":         []string{"https://login.example.com"},
		"iat":         now.Add(-time.Minute).Unix(),
		"nbf":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(9 * time.Minute).Unix(),
		"jti":         "token-1",
		"environment": "prod",
	}
	for _, m := range modify {
		m(claims)
	}
	return claims
}

func assertInvalidGrant(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var oidcErr *oidc.Error
	require.ErrorAs(t, err, &oidcErr)
	assert.Equal(t, oidc.InvalidGrant, oidcErr.ErrorType)
}

// TestFederatedCredentialExchange_accepts exchanges a valid token of each allowed algorithm,
// ES256 (P-256) included, with the keys fetched from the issuer's published metadata.
func TestFederatedCredentialExchange_accepts(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.ES256, jose.RS256, jose.EdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			f := newExchangeFixture(t, alg, testCredential())
			claims := f.claims()
			match, err := f.ex.match(context.Background(), f.key.sign(t, claims))
			require.NoError(t, err)
			require.NotNil(t, match)

			assert.Equal(t, "cred1", match.credential.ID)
			assert.Equal(t, 10*time.Minute, match.credential.MaxTokenLifetime)
			assert.Equal(t, &domain.FederatedCredentialExchange{
				CredentialID:  "cred1",
				UserID:        "machine1",
				ResourceOwner: "org1",
				Issuer:        f.issuer.server.URL,
				Subject:       "repo:example/app",
				SubjectClaim:  "sub",
				SubjectValue:  "repo:example/app",
				TokenID:       "token-1",
				AssertionKey:  domain.FederatedCredentialAssertionKey(f.issuer.server.URL, "token-1", "", time.Unix(claims["exp"].(int64), 0)),
			}, match.exchange)
			assert.True(t, strings.HasPrefix(match.exchange.AssertionKey, strconv.FormatInt(claims["exp"].(int64), 10)+":"))
			assert.Equal(t, int32(1), f.issuer.metadataHits.Load())
			assert.Equal(t, int32(1), f.issuer.keyHits.Load())
		})
	}
}

// Assertions that are not for a federated credential are left to the key path: nothing is looked
// up for an assertion a machine user signed with its own key (its issuer is the user ID), and an
// https issuer that no enabled credential names exactly is not handled either.
func TestFederatedCredentialExchange_leavesOtherAssertionsToTheKeyPath(t *testing.T) {
	f := newExchangeFixture(t, jose.RS256, testCredential())
	machineKey := newTestIssuerKey(t, "machine-key-id", jose.RS256)
	now := f.clock.Now()

	t.Run("assertion signed with a machine user's own key", func(t *testing.T) {
		lookups := f.store.lookups.Load()
		assertion := machineKey.sign(t, map[string]any{
			"iss": "312909075211944344", "sub": "312909075211944344", "aud": []string{"https://login.example.com"},
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		match, err := f.ex.match(context.Background(), assertion)
		require.NoError(t, err)
		assert.Nil(t, match)
		assert.Equal(t, lookups, f.store.lookups.Load(), "no credential lookup for a key-signed assertion")
	})
	for name, assertion := range map[string]string{
		"not a JWT":                          "not-a-jwt",
		"payload is not JSON":                "eyJhbGciOiJSUzI1NiJ9.bm90LWpzb24.c2ln",
		"https issuer without a credential":  f.key.sign(t, f.claims(func(c map[string]any) { c["iss"] = "https://unregistered.example.com" })),
		"issuer differs by a trailing slash": f.key.sign(t, f.claims(func(c map[string]any) { c["iss"] = f.issuer.server.URL + "/" })),
		"http issuer":                        f.key.sign(t, f.claims(func(c map[string]any) { c["iss"] = "http" + strings.TrimPrefix(f.issuer.server.URL, "https") })),
	} {
		t.Run(name, func(t *testing.T) {
			match, err := f.ex.match(context.Background(), assertion)
			require.NoError(t, err)
			assert.Nil(t, match)
		})
	}
	t.Run("no exchanger configured", func(t *testing.T) {
		var ex *federatedCredentialExchanger
		match, err := ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)
		assert.Nil(t, match)
	})
}

// TestFederatedCredentialExchange_refuses: once the issuer is registered, an assertion that no
// credential accepts is refused with invalid_grant and never falls back to the key path.
func TestFederatedCredentialExchange_refuses(t *testing.T) {
	tests := []struct {
		name       string
		credential func(*query.FederatedCredential)
		claims     func(f *exchangeFixture, c map[string]any)
		sign       func(t *testing.T, f *exchangeFixture, claims map[string]any) string
	}{
		{
			name:       "algorithm outside the credential's allow-list",
			credential: func(c *query.FederatedCredential) { c.Algorithms = []string{"RS256", "EdDSA"} },
		},
		{
			name: "algorithm outside every allow-list (HS256)",
			sign: func(t *testing.T, f *exchangeFixture, claims map[string]any) string {
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
				require.NoError(t, err)
				payload, err := json.Marshal(claims)
				require.NoError(t, err)
				signed, err := signer.Sign(payload)
				require.NoError(t, err)
				compact, err := signed.CompactSerialize()
				require.NoError(t, err)
				return compact
			},
		},
		{
			name:   "wrong audience",
			claims: func(_ *exchangeFixture, c map[string]any) { c["aud"] = []string{"https://other.example.com"} },
		},
		{
			name:   "audience missing",
			claims: func(_ *exchangeFixture, c map[string]any) { delete(c, "aud") },
		},
		{
			name:   "subject that fails the rule",
			claims: func(_ *exchangeFixture, c map[string]any) { c["sub"] = "repo:example/other" },
		},
		{
			name: "subject that fails a pattern",
			credential: func(c *query.FederatedCredential) {
				c.SubjectRule = domain.FederatedCredentialSubjectRule{Claim: "sub", Pattern: `repo:example/app:ref:refs/heads/.+`}
			},
		},
		{
			name:   "claim condition that fails",
			claims: func(_ *exchangeFixture, c map[string]any) { c["environment"] = "staging" },
		},
		{
			name:   "claim condition on a missing claim",
			claims: func(_ *exchangeFixture, c map[string]any) { delete(c, "environment") },
		},
		{
			name: "older than the maximum age, though unexpired",
			claims: func(f *exchangeFixture, c map[string]any) {
				c["iat"] = f.clock.Now().Add(-6 * time.Minute).Unix()
				c["exp"] = f.clock.Now().Add(time.Hour).Unix()
			},
		},
		{
			name:   "no issue time",
			claims: func(_ *exchangeFixture, c map[string]any) { delete(c, "iat") },
		},
		{
			name:   "issue time that is not a number",
			claims: func(f *exchangeFixture, c map[string]any) { c["iat"] = strconv.FormatInt(f.clock.Now().Unix(), 10) },
		},
		{
			name:   "issue time in the future",
			claims: func(f *exchangeFixture, c map[string]any) { c["iat"] = f.clock.Now().Add(5 * time.Minute).Unix() },
		},
		{
			name:   "expired",
			claims: func(f *exchangeFixture, c map[string]any) { c["exp"] = f.clock.Now().Add(-2 * time.Minute).Unix() },
		},
		{
			name:   "no expiration",
			claims: func(_ *exchangeFixture, c map[string]any) { delete(c, "exp") },
		},
		{
			name:   "not valid yet",
			claims: func(f *exchangeFixture, c map[string]any) { c["nbf"] = f.clock.Now().Add(5 * time.Minute).Unix() },
		},
		{
			name:   "jti that is not a string",
			claims: func(_ *exchangeFixture, c map[string]any) { c["jti"] = 42 },
		},
		{
			name: "signed by another key under the same key ID",
			sign: func(t *testing.T, f *exchangeFixture, claims map[string]any) string {
				return newTestIssuerKey(t, f.key.kid, f.key.alg).sign(t, claims)
			},
		},
		{
			name: "signed by a key the issuer does not publish",
			sign: func(t *testing.T, f *exchangeFixture, claims map[string]any) string {
				return newTestIssuerKey(t, "unpublished", f.key.alg).sign(t, claims)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modify := []func(*query.FederatedCredential){}
			if tt.credential != nil {
				modify = append(modify, tt.credential)
			}
			f := newExchangeFixture(t, jose.ES256, testCredential(modify...))
			claims := f.claims()
			if tt.claims != nil {
				tt.claims(f, claims)
			}
			assertion := ""
			if tt.sign != nil {
				assertion = tt.sign(t, f, claims)
			} else {
				assertion = f.key.sign(t, claims)
			}
			match, err := f.ex.match(context.Background(), assertion)
			assertInvalidGrant(t, err)
			assert.Nil(t, match)
		})
	}
}

// The exchange does not trust the read model's filter alone: a disabled credential, or one whose
// issuer is not exactly the token's, accepts nothing even when the lookup returns it.
func TestFederatedCredentialExchange_checksEachCredential(t *testing.T) {
	t.Run("disabled credential", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256, testCredential(func(c *query.FederatedCredential) { c.Disabled = true }))
		match, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err, "a disabled credential is not found: the key path refuses the assertion")
		assert.Nil(t, match)

		f.store.raw = true
		match, err = f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		assertInvalidGrant(t, err)
		assert.Nil(t, match)
	})
	t.Run("issuer that is not an exact match", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256, testCredential(func(c *query.FederatedCredential) { c.Issuer += "/" }))
		f.store.raw = true
		match, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		assertInvalidGrant(t, err)
		assert.Nil(t, match)
	})
}

// TestFederatedCredentialExchange_ambiguous: the patterns of credentials cannot be checked for
// overlap when they are written, so an assertion that the enabled credentials of more than one
// machine user accept is refused. Several credentials of one user are not ambiguous; the
// smallest token lifetime cap among them applies.
func TestFederatedCredentialExchange_ambiguous(t *testing.T) {
	broad := func(c *query.FederatedCredential) {
		c.SubjectRule = domain.FederatedCredentialSubjectRule{Claim: "sub", Pattern: `repo:example/.+`}
	}
	t.Run("credentials of two machine users", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256,
			testCredential(),
			testCredential(broad, func(c *query.FederatedCredential) { c.ID, c.UserID = "cred2", "machine2" }),
		)
		match, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		assertInvalidGrant(t, err)
		var oidcErr *oidc.Error
		require.ErrorAs(t, err, &oidcErr)
		assert.Contains(t, oidcErr.Description, "more than one machine user")
		assert.Nil(t, match)
	})
	t.Run("two users, but only one credential accepts the token", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256,
			testCredential(),
			testCredential(func(c *query.FederatedCredential) {
				c.ID, c.UserID = "cred2", "machine2"
				c.SubjectRule.Exact = "repo:example/other"
			}),
		)
		match, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)
		require.NotNil(t, match)
		assert.Equal(t, "machine1", match.exchange.UserID)
	})
	t.Run("two credentials of the same machine user", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256,
			testCredential(),
			testCredential(broad, func(c *query.FederatedCredential) { c.ID, c.MaxTokenLifetime = "cred2", 2*time.Minute }),
		)
		match, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)
		require.NotNil(t, match)
		assert.Equal(t, "cred2", match.exchange.CredentialID)
		assert.Equal(t, 2*time.Minute, match.credential.MaxTokenLifetime)
	})
}

// TestFederatedCredentialExchange_subjectRuleOnAnotherClaim records the matched claim and its
// value, beside the token's own sub.
func TestFederatedCredentialExchange_subjectRuleOnAnotherClaim(t *testing.T) {
	f := newExchangeFixture(t, jose.ES256, testCredential(func(c *query.FederatedCredential) {
		c.SubjectRule = domain.FederatedCredentialSubjectRule{Claim: "repository_id", Exact: "123456"}
	}))
	match, err := f.ex.match(context.Background(), f.key.sign(t, f.claims(func(c map[string]any) {
		c["repository_id"] = "123456"
		delete(c, "jti")
	})))
	require.NoError(t, err)
	require.NotNil(t, match)
	assert.Equal(t, "repo:example/app", match.exchange.Subject)
	assert.Equal(t, "repository_id", match.exchange.SubjectClaim)
	assert.Equal(t, "123456", match.exchange.SubjectValue)
	assert.Empty(t, match.exchange.TokenID)
}

// TestFederatedCredentialExchange_singleUseKey: the push that records the exchange refuses a key it
// has seen (command.WithFederatedCredentialExchange), so the key must identify the token however it
// is spelled. Without a jti the key is the canonical signing input's: an ECDSA signature rewritten
// as (r, n-s), or a payload spelled with a line break, still verifies and must not make a second,
// unused token.
func TestFederatedCredentialExchange_singleUseKey(t *testing.T) {
	f := newExchangeFixture(t, jose.ES256, testCredential())
	assertion := f.key.sign(t, f.claims(func(c map[string]any) { delete(c, "jti") }))

	first, err := f.ex.match(context.Background(), assertion)
	require.NoError(t, err)
	require.NotNil(t, first)
	again, err := f.ex.match(context.Background(), assertion)
	require.NoError(t, err)
	require.NotNil(t, again)
	assert.Equal(t, first.exchange.AssertionKey, again.exchange.AssertionKey)

	malleated := malleateES256(t, assertion)
	require.NotEqual(t, assertion, malleated)
	rewritten, err := f.ex.match(context.Background(), malleated)
	require.NoError(t, err, "the rewritten signature verifies")
	require.NotNil(t, rewritten)
	assert.Equal(t, first.exchange.AssertionKey, rewritten.exchange.AssertionKey)

	// The base64url decoder skips line breaks, so the payload can be spelled differently.
	parts := strings.Split(assertion, ".")
	respelled := parts[0] + "." + parts[1][:8] + "\n" + parts[1][8:] + "." + parts[2]
	respelledMatch, err := f.ex.match(context.Background(), respelled)
	require.NoError(t, err, "the respelled token verifies")
	require.NotNil(t, respelledMatch)
	assert.Equal(t, first.exchange.AssertionKey, respelledMatch.exchange.AssertionKey)

	other, err := f.ex.match(context.Background(), f.key.sign(t, f.claims(func(c map[string]any) {
		delete(c, "jti")
		c["iat"] = f.clock.Now().Add(-30 * time.Second).Unix()
	})))
	require.NoError(t, err)
	require.NotNil(t, other)
	assert.NotEqual(t, first.exchange.AssertionKey, other.exchange.AssertionKey)
}

// malleateES256 rewrites the signature (r, s) of a compact ES256 token as (r, n-s).
func malleateES256(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, signature, 64)
	s := new(big.Int).SetBytes(signature[32:])
	s.Sub(elliptic.P256().Params().N, s)
	rewritten := append([]byte{}, signature[:32]...)
	rewritten = append(rewritten, s.FillBytes(make([]byte, 32))...)
	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(rewritten)
}

// TestFederatedIssuerKeys covers the key source: a rotated key is fetched when a token names it,
// fetches are rate limited, cached keys expire, a failed fetch fails closed, and the metadata must
// name the issuer.
func TestFederatedIssuerKeys(t *testing.T) {
	t.Run("a rotated key is picked up", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256, testCredential())
		_, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)

		rotated := newTestIssuerKey(t, "key2", jose.ES256)
		f.issuer.setKeys(f.key, rotated)
		f.clock.advance(f.keys.refetchInterval)
		match, err := f.ex.match(context.Background(), rotated.sign(t, f.claims()))
		require.NoError(t, err)
		require.NotNil(t, match)
		assert.Equal(t, int32(2), f.issuer.keyHits.Load())
	})
	t.Run("unknown key IDs cause at most one fetch per interval", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256, testCredential())
		_, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)
		require.Equal(t, int32(1), f.issuer.keyHits.Load())

		f.clock.advance(f.keys.refetchInterval)
		for i := range 5 {
			_, err = f.ex.match(context.Background(), newTestIssuerKey(t, "made-up-"+strconv.Itoa(i), jose.ES256).sign(t, f.claims()))
			assertInvalidGrant(t, err)
		}
		assert.Equal(t, int32(2), f.issuer.keyHits.Load(), "one refetch for the first unknown key ID, none for the rest")

		// A known key keeps working from the cache meanwhile.
		_, err = f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)
		assert.Equal(t, int32(2), f.issuer.keyHits.Load())
	})
	t.Run("cached keys are fetched again after their lifetime", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256, testCredential())
		_, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)
		f.clock.advance(f.keys.ttl)
		_, err = f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)
		assert.Equal(t, int32(2), f.issuer.keyHits.Load())
	})
	t.Run("a withdrawn key stops working once the cache expires", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256, testCredential())
		_, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)
		f.issuer.setKeys(newTestIssuerKey(t, "key2", jose.ES256))
		f.clock.advance(f.keys.ttl)
		_, err = f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		assertInvalidGrant(t, err)
	})
	t.Run("expired keys are not used when the fetch fails", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256, testCredential())
		_, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		require.NoError(t, err)
		f.issuer.setFail(true)
		f.clock.advance(f.keys.ttl)
		_, err = f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		assertInvalidGrant(t, err)
		assert.True(t, errors.Is(err, errFederatedKeysUnavailable))
	})
	t.Run("metadata that names another issuer", func(t *testing.T) {
		f := newExchangeFixture(t, jose.ES256, testCredential())
		f.issuer.metadataIssuer = "https://impostor.example.com"
		_, err := f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		assertInvalidGrant(t, err)
		assert.Equal(t, int32(0), f.issuer.keyHits.Load())
	})
	t.Run("pinned keys are used instead of the metadata", func(t *testing.T) {
		pinned := newTestIssuerKey(t, "pinned1", jose.ES256)
		jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pinned.publicJWK()}})
		require.NoError(t, err)
		f := newExchangeFixture(t, jose.ES256, testCredential(func(c *query.FederatedCredential) {
			c.KeySource = domain.FederatedCredentialKeySourcePinnedKeys
			c.PinnedKeys = string(jwks)
		}))
		match, err := f.ex.match(context.Background(), pinned.sign(t, f.claims()))
		require.NoError(t, err)
		require.NotNil(t, match)

		_, err = f.ex.match(context.Background(), f.key.sign(t, f.claims()))
		assertInvalidGrant(t, err)
		assert.Equal(t, int32(0), f.issuer.metadataHits.Load(), "the issuer's metadata is not fetched")
		assert.Equal(t, int32(0), f.issuer.keyHits.Load())
	})
}

// The server fetches issuer keys through publicfetch.NewClient(): an issuer on a loopback address
// and a non-standard port is refused before anything reaches it.
func TestFederatedIssuerKeys_publicOnlyClient(t *testing.T) {
	f := newExchangeFixture(t, jose.ES256, testCredential())
	keys := newFederatedIssuerKeys(publicfetch.NewClient())
	_, err := keys.key(context.Background(), f.issuer.server.URL, f.key.kid)
	require.Error(t, err)
	assert.True(t, errors.Is(err, publicfetch.ErrDenied))
	assert.Equal(t, int32(0), f.issuer.metadataHits.Load())
}

// TestServer_federatedCredentialJWTProfile_keyPathUnchanged: the grant hands every assertion that is
// not for a federated credential to its key path before looking anything else up, so a machine
// user's own key keeps working as before.
func TestServer_federatedCredentialJWTProfile_keyPathUnchanged(t *testing.T) {
	f := newExchangeFixture(t, jose.RS256, testCredential())
	machineKey := newTestIssuerKey(t, "machine-key-id", jose.RS256)
	now := time.Now()
	keySigned := machineKey.sign(t, map[string]any{
		"iss": "312909075211944344", "sub": "312909075211944344", "aud": []string{"https://login.example.com"},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	for name, server := range map[string]*Server{
		"exchanger configured":    {federatedCredentials: f.ex},
		"no exchanger configured": {},
	} {
		t.Run(name, func(t *testing.T) {
			handled, resp, err := server.federatedCredentialJWTProfile(context.Background(), &op.Request[oidc.JWTProfileGrantRequest]{
				Data: &oidc.JWTProfileGrantRequest{Assertion: keySigned, GrantType: oidc.GrantTypeBearer},
			})
			require.NoError(t, err)
			assert.False(t, handled)
			assert.Nil(t, resp)
		})
	}
	assert.Equal(t, int32(0), f.store.lookups.Load())

	t.Run("a refused federated assertion is handled, not passed on", func(t *testing.T) {
		server := &Server{federatedCredentials: f.ex}
		handled, resp, err := server.federatedCredentialJWTProfile(context.Background(), &op.Request[oidc.JWTProfileGrantRequest]{
			Data: &oidc.JWTProfileGrantRequest{
				Assertion: f.key.sign(t, f.claims(func(c map[string]any) { c["sub"] = "repo:example/other" })),
				GrantType: oidc.GrantTypeBearer,
			},
		})
		assert.True(t, handled)
		assert.Nil(t, resp)
		assertInvalidGrant(t, err)
	})
}

// The session's authentication method shows in the token's introspection and in an ID token: a
// federated credential exchange is told apart from a machine key, which has no value.
func TestAMR_federatedCredential(t *testing.T) {
	assert.Equal(t, []string{FederatedCredential}, AuthMethodTypesToAMR([]domain.UserAuthMethodType{domain.UserAuthMethodTypeFederatedCredential}))
	assert.Empty(t, AuthMethodTypesToAMR([]domain.UserAuthMethodType{domain.UserAuthMethodTypePrivateKey}))
}
