package domain

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/zerrors"
)

func validFederatedCredential() *FederatedCredential {
	return &FederatedCredential{
		Issuer:     "https://token.ci.example.com",
		KeySource:  FederatedCredentialKeySourceIssuerMetadata,
		Algorithms: []string{"RS256", "ES256"},
		Audience:   "https://auth.example.com",
		SubjectRule: FederatedCredentialSubjectRule{
			Claim: "sub",
			Exact: "repo:acme/deploy:ref:refs/heads/main",
		},
		ClaimConditions: []FederatedCredentialClaimCondition{
			{Claim: "repository_id", Value: "123456"},
		},
		MaxTokenAge:      10 * time.Minute,
		MaxTokenLifetime: 5 * time.Minute,
	}
}

func jwks(t *testing.T, keys ...jose.JSONWebKey) string {
	t.Helper()
	data, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	require.NoError(t, err)
	return string(data)
}

type testKeys struct {
	rsa2048 *rsa.PrivateKey
	rsa1024 *rsa.PrivateKey
	p256    *ecdsa.PrivateKey
	p384    *ecdsa.PrivateKey
	ed      ed25519.PrivateKey
}

func newTestKeys(t *testing.T) testKeys {
	t.Helper()
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return testKeys{rsa2048: rsa2048, rsa1024: rsa1024, p256: p256, p384: p384, ed: ed}
}

func TestFederatedCredential_Validate(t *testing.T) {
	keys := newTestKeys(t)
	pinned := func(set string, algorithms ...string) func(*FederatedCredential) {
		return func(c *FederatedCredential) {
			c.KeySource = FederatedCredentialKeySourcePinnedKeys
			c.PinnedKeys = set
			if len(algorithms) > 0 {
				c.Algorithms = algorithms
			}
		}
	}
	tests := []struct {
		name    string
		modify  func(*FederatedCredential)
		wantErr string
	}{
		{name: "valid with issuer metadata", modify: func(*FederatedCredential) {}},
		{name: "valid issuer with path and trailing slash", modify: func(c *FederatedCredential) { c.Issuer = "https://issuer.example.com/tenant/" }},
		{name: "valid pattern", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: `repo:acme/[a-z-]+:ref:refs/heads/main`}
		}},
		{name: "valid pattern with alternation sharing a prefix", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: `system:serviceaccount:(?:ns-a|ns-b):deployer`}
		}},
		{name: "valid without conditions", modify: func(c *FederatedCredential) { c.ClaimConditions = nil }},
		{name: "valid all algorithms", modify: func(c *FederatedCredential) { c.Algorithms = []string{"ES256", "RS256", "EdDSA"} }},
		{name: "valid pinned RSA, P-256 and Ed25519 keys", modify: pinned(jwks(t,
			jose.JSONWebKey{Key: keys.rsa2048.Public(), KeyID: "rsa", Use: "sig", Algorithm: "RS256"},
			jose.JSONWebKey{Key: keys.p256.Public(), KeyID: "ec"},
			jose.JSONWebKey{Key: keys.ed.Public(), KeyID: "ed"},
		), "RS256", "ES256", "EdDSA")},
		{name: "valid pinned keys for an issuer that cannot be fetched", modify: func(c *FederatedCredential) {
			pinned(jwks(t, jose.JSONWebKey{Key: keys.p256.Public(), KeyID: "ec"}))(c)
			c.Issuer = "https://kubernetes.default.svc:6443"
		}},

		// issuer
		{name: "issuer empty", modify: func(c *FederatedCredential) { c.Issuer = "" }, wantErr: "IssuerInvalid"},
		{name: "issuer http", modify: func(c *FederatedCredential) { c.Issuer = "http://token.ci.example.com" }, wantErr: "IssuerInvalid"},
		{name: "issuer upper case scheme", modify: func(c *FederatedCredential) { c.Issuer = "HTTPS://token.ci.example.com" }, wantErr: "IssuerInvalid"},
		{name: "issuer without host", modify: func(c *FederatedCredential) { c.Issuer = "https:///path" }, wantErr: "IssuerInvalid"},
		{name: "issuer with query", modify: func(c *FederatedCredential) { c.Issuer = "https://token.ci.example.com?x=1" }, wantErr: "IssuerInvalid"},
		{name: "issuer with fragment", modify: func(c *FederatedCredential) { c.Issuer = "https://token.ci.example.com#a" }, wantErr: "IssuerInvalid"},
		{name: "issuer with empty fragment", modify: func(c *FederatedCredential) { c.Issuer = "https://token.ci.example.com#" }, wantErr: "IssuerInvalid"},
		{name: "issuer with user info", modify: func(c *FederatedCredential) { c.Issuer = "https://user@token.ci.example.com" }, wantErr: "IssuerInvalid"},
		{name: "issuer with white space", modify: func(c *FederatedCredential) { c.Issuer = "https://token.ci.example.com/ a" }, wantErr: "IssuerInvalid"},
		{name: "issuer too long", modify: func(c *FederatedCredential) { c.Issuer = "https://a.example.com/" + strings.Repeat("a", 1024) }, wantErr: "IssuerInvalid"},
		{name: "issuer metadata on another port", modify: func(c *FederatedCredential) { c.Issuer = "https://token.ci.example.com:8443" }, wantErr: "IssuerNotFetchable"},
		{name: "issuer metadata on a private address", modify: func(c *FederatedCredential) { c.Issuer = "https://10.0.0.1" }, wantErr: "IssuerNotFetchable"},
		{name: "issuer metadata on loopback", modify: func(c *FederatedCredential) { c.Issuer = "https://[::1]" }, wantErr: "IssuerNotFetchable"},

		// key source
		{name: "key source missing", modify: func(c *FederatedCredential) { c.KeySource = FederatedCredentialKeySourceUnspecified }, wantErr: "KeySourceMissing"},
		{name: "key source unknown", modify: func(c *FederatedCredential) { c.KeySource = 7 }, wantErr: "KeySourceMissing"},
		{name: "issuer metadata with pinned keys", modify: func(c *FederatedCredential) {
			c.PinnedKeys = jwks(t, jose.JSONWebKey{Key: keys.p256.Public(), KeyID: "ec"})
		}, wantErr: "PinnedKeysInvalid"},
		{name: "pinned keys empty", modify: pinned(""), wantErr: "PinnedKeysInvalid"},
		{name: "pinned keys not JSON", modify: pinned("not json"), wantErr: "PinnedKeysInvalid"},
		{name: "pinned keys empty set", modify: pinned(`{"keys":[]}`), wantErr: "PinnedKeysInvalid"},
		{name: "pinned private key", modify: pinned(jwks(t, jose.JSONWebKey{Key: keys.p256, KeyID: "ec"})), wantErr: "PinnedKeysInvalid"},
		{name: "pinned symmetric key", modify: pinned(jwks(t, jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef"), KeyID: "hs"})), wantErr: "PinnedKeysInvalid"},
		{name: "pinned key without key ID", modify: pinned(jwks(t, jose.JSONWebKey{Key: keys.p256.Public()})), wantErr: "PinnedKeysInvalid"},
		{name: "pinned keys with a duplicate key ID", modify: pinned(jwks(t,
			jose.JSONWebKey{Key: keys.p256.Public(), KeyID: "k"},
			jose.JSONWebKey{Key: keys.rsa2048.Public(), KeyID: "k"},
		)), wantErr: "PinnedKeysInvalid"},
		{name: "pinned RSA key below 2048 bits", modify: pinned(jwks(t, jose.JSONWebKey{Key: keys.rsa1024.Public(), KeyID: "rsa"})), wantErr: "PinnedKeysInvalid"},
		{name: "pinned P-384 key", modify: pinned(jwks(t, jose.JSONWebKey{Key: keys.p384.Public(), KeyID: "ec"})), wantErr: "PinnedKeysInvalid"},
		{name: "pinned key for an algorithm not allowed", modify: pinned(jwks(t, jose.JSONWebKey{Key: keys.ed.Public(), KeyID: "ed"}), "ES256"), wantErr: "PinnedKeysInvalid"},
		{name: "pinned key with a mismatching alg", modify: pinned(jwks(t, jose.JSONWebKey{Key: keys.p256.Public(), KeyID: "ec", Algorithm: "RS256"})), wantErr: "PinnedKeysInvalid"},
		{name: "pinned key for encryption", modify: pinned(jwks(t, jose.JSONWebKey{Key: keys.p256.Public(), KeyID: "ec", Use: "enc"})), wantErr: "PinnedKeysInvalid"},

		// algorithms
		{name: "algorithms missing", modify: func(c *FederatedCredential) { c.Algorithms = nil }, wantErr: "AlgorithmsMissing"},
		{name: "algorithm none", modify: func(c *FederatedCredential) { c.Algorithms = []string{"none"} }, wantErr: "AlgorithmUnsupported"},
		{name: "algorithm HS256", modify: func(c *FederatedCredential) { c.Algorithms = []string{"RS256", "HS256"} }, wantErr: "AlgorithmUnsupported"},
		{name: "algorithm PS256", modify: func(c *FederatedCredential) { c.Algorithms = []string{"PS256"} }, wantErr: "AlgorithmUnsupported"},
		{name: "algorithm ES384", modify: func(c *FederatedCredential) { c.Algorithms = []string{"ES384"} }, wantErr: "AlgorithmUnsupported"},
		{name: "algorithm in wrong case", modify: func(c *FederatedCredential) { c.Algorithms = []string{"es256"} }, wantErr: "AlgorithmUnsupported"},
		{name: "algorithm repeated", modify: func(c *FederatedCredential) { c.Algorithms = []string{"ES256", "ES256"} }, wantErr: "AlgorithmUnsupported"},

		// audience
		{name: "audience missing", modify: func(c *FederatedCredential) { c.Audience = "" }, wantErr: "AudienceMissing"},
		{name: "audience with white space", modify: func(c *FederatedCredential) { c.Audience = "a b" }, wantErr: "AudienceInvalid"},
		{name: "audience too long", modify: func(c *FederatedCredential) { c.Audience = strings.Repeat("a", 1025) }, wantErr: "AudienceInvalid"},

		// subject rule
		{name: "subject rule empty", modify: func(c *FederatedCredential) { c.SubjectRule = FederatedCredentialSubjectRule{} }, wantErr: "SubjectRuleInvalid"},
		{name: "subject rule without claim", modify: func(c *FederatedCredential) { c.SubjectRule.Claim = "" }, wantErr: "SubjectRuleInvalid"},
		{name: "subject rule without value", modify: func(c *FederatedCredential) { c.SubjectRule.Exact = "" }, wantErr: "SubjectRuleInvalid"},
		{name: "subject rule with exact value and pattern", modify: func(c *FederatedCredential) { c.SubjectRule.Pattern = "repo:.*" }, wantErr: "SubjectRuleInvalid"},
		{name: "subject exact value with control character", modify: func(c *FederatedCredential) { c.SubjectRule.Exact = "a\nb" }, wantErr: "SubjectRuleInvalid"},
		{name: "subject claim with white space", modify: func(c *FederatedCredential) { c.SubjectRule.Claim = "my claim" }, wantErr: "ClaimInvalid"},
		{name: "subject claim reserved", modify: func(c *FederatedCredential) { c.SubjectRule.Claim = "aud" }, wantErr: "ClaimInvalid"},
		{name: "subject claim too long", modify: func(c *FederatedCredential) { c.SubjectRule.Claim = strings.Repeat("c", 257) }, wantErr: "ClaimInvalid"},
		{name: "subject pattern does not parse", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: "repo:(acme"}
		}, wantErr: "SubjectPatternInvalid"},
		{name: "subject pattern escaping the anchors", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: "repo:a)|(.*"}
		}, wantErr: "SubjectPatternInvalid"},
		{name: "subject pattern matching everything", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: ".*"}
		}, wantErr: "SubjectPatternTooBroad"},
		{name: "subject pattern matching every non-empty value", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: ".+"}
		}, wantErr: "SubjectPatternTooBroad"},
		{name: "subject pattern matching everything across lines", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: `(?s).*`}
		}, wantErr: "SubjectPatternTooBroad"},
		{name: "subject pattern with a class first", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: `[\s\S]*`}
		}, wantErr: "SubjectPatternTooBroad"},
		{name: "subject pattern with an alternative matching everything", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: `repo:acme/x|.*`}
		}, wantErr: "SubjectPatternTooBroad"},
		{name: "subject pattern with an own anchor only", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: `^.*$`}
		}, wantErr: "SubjectPatternTooBroad"},
		{name: "subject pattern case insensitive", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: `(?i)repo:.*`}
		}, wantErr: "SubjectPatternTooBroad"},
		{name: "subject pattern starting with an optional literal", modify: func(c *FederatedCredential) {
			c.SubjectRule = FederatedCredentialSubjectRule{Claim: "sub", Pattern: `(?:repo:)?.*`}
		}, wantErr: "SubjectPatternTooBroad"},

		// conditions
		{name: "condition without claim", modify: func(c *FederatedCredential) { c.ClaimConditions[0].Claim = "" }, wantErr: "ConditionInvalid"},
		{name: "condition without value", modify: func(c *FederatedCredential) { c.ClaimConditions[0].Value = "" }, wantErr: "ConditionInvalid"},
		{name: "condition on a reserved claim", modify: func(c *FederatedCredential) { c.ClaimConditions[0].Claim = "iss" }, wantErr: "ConditionInvalid"},
		{name: "condition repeated for a claim", modify: func(c *FederatedCredential) {
			c.ClaimConditions = append(c.ClaimConditions, FederatedCredentialClaimCondition{Claim: "repository_id", Value: "7"})
		}, wantErr: "ConditionInvalid"},
		{name: "too many conditions", modify: func(c *FederatedCredential) {
			c.ClaimConditions = nil
			for i := 0; i < 21; i++ {
				c.ClaimConditions = append(c.ClaimConditions, FederatedCredentialClaimCondition{Claim: "c" + strings.Repeat("x", i), Value: "v"})
			}
		}, wantErr: "ConditionInvalid"},

		// durations
		{name: "max token age missing", modify: func(c *FederatedCredential) { c.MaxTokenAge = 0 }, wantErr: "MaxTokenAgeInvalid"},
		{name: "max token age negative", modify: func(c *FederatedCredential) { c.MaxTokenAge = -time.Minute }, wantErr: "MaxTokenAgeInvalid"},
		{name: "max token age above a day", modify: func(c *FederatedCredential) { c.MaxTokenAge = 25 * time.Hour }, wantErr: "MaxTokenAgeInvalid"},
		{name: "max token lifetime missing", modify: func(c *FederatedCredential) { c.MaxTokenLifetime = 0 }, wantErr: "MaxTokenLifetimeInvalid"},
		{name: "max token lifetime above an hour", modify: func(c *FederatedCredential) { c.MaxTokenLifetime = time.Hour + time.Second }, wantErr: "MaxTokenLifetimeInvalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validFederatedCredential()
			tt.modify(c)
			err := c.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.True(t, zerrors.IsErrorInvalidArgument(err), "want invalid argument, got %v", err)
			var zErr *zerrors.ZitadelError
			require.ErrorAs(t, err, &zErr)
			assert.Equal(t, "Errors.User.Machine.FederatedCredential."+tt.wantErr, zErr.GetMessage())
		})
	}
}

func TestFederatedCredential_MetadataURL(t *testing.T) {
	tests := []struct {
		issuer string
		want   string
	}{
		{"https://token.ci.example.com", "https://token.ci.example.com/.well-known/openid-configuration"},
		{"https://token.ci.example.com/", "https://token.ci.example.com/.well-known/openid-configuration"},
		{"https://issuer.example.com/tenant", "https://issuer.example.com/tenant/.well-known/openid-configuration"},
		{"https://issuer.example.com/tenant/", "https://issuer.example.com/tenant/.well-known/openid-configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			c := &FederatedCredential{Issuer: tt.issuer}
			assert.Equal(t, tt.want, c.MetadataURL())
		})
	}
}

func TestFederatedCredentialSubjectRule_Matches(t *testing.T) {
	exact := FederatedCredentialSubjectRule{Claim: "sub", Exact: "system:serviceaccount:ci:deployer"}
	pattern := FederatedCredentialSubjectRule{Claim: "sub", Pattern: `repo:acme/[a-z]+:ref:refs/heads/main`}
	tests := []struct {
		name  string
		rule  FederatedCredentialSubjectRule
		value string
		want  bool
	}{
		{"exact equal", exact, "system:serviceaccount:ci:deployer", true},
		{"exact prefix only", exact, "system:serviceaccount:ci:deployer-2", false},
		{"exact other case", exact, "System:serviceaccount:ci:deployer", false},
		{"exact empty", exact, "", false},
		{"pattern match", pattern, "repo:acme/deploy:ref:refs/heads/main", true},
		{"pattern is anchored at the start", pattern, "x-repo:acme/deploy:ref:refs/heads/main", false},
		{"pattern is anchored at the end", pattern, "repo:acme/deploy:ref:refs/heads/main-evil", false},
		{"pattern does not match a newline", pattern, "repo:acme/deploy:ref:refs/heads/main\n", false},
		{"pattern other value", pattern, "repo:other/deploy:ref:refs/heads/main", false},
		{"pattern empty", pattern, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.rule.Matches(tt.value))
		})
	}
}

func TestFederatedCredential_MatchesClaims(t *testing.T) {
	c := validFederatedCredential()
	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"subject and condition match", map[string]any{"sub": "repo:acme/deploy:ref:refs/heads/main", "repository_id": "123456"}, true},
		{"condition fails", map[string]any{"sub": "repo:acme/deploy:ref:refs/heads/main", "repository_id": "654321"}, false},
		{"condition missing", map[string]any{"sub": "repo:acme/deploy:ref:refs/heads/main"}, false},
		{"condition not a string", map[string]any{"sub": "repo:acme/deploy:ref:refs/heads/main", "repository_id": 123456}, false},
		{"subject fails", map[string]any{"sub": "repo:acme/other:ref:refs/heads/main", "repository_id": "123456"}, false},
		{"subject missing", map[string]any{"repository_id": "123456"}, false},
		{"subject not a string", map[string]any{"sub": []string{"repo:acme/deploy:ref:refs/heads/main"}, "repository_id": "123456"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, c.MatchesClaims(tt.claims))
		})
	}
}
