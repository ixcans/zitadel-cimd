package domain

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"

	"github.com/zitadel/zitadel/internal/publicfetch"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// A federated credential lets a machine user authenticate with a token that a foreign issuer
// signed (a workload platform, a CI system, another identity provider), instead of with a key the
// machine user holds. The credential names the issuer, where its verification keys come from,
// which algorithms and which audience it must use, which subject (and other claims) it must carry,
// how old the token may be, and how long the machine token issued in exchange may live.
//
// Managing federated credentials needs its own permissions, separate from user.write, which manages
// the machine user's own keys: being allowed to add a key to a machine user does not make a caller
// allowed to let a foreign issuer act as it.
const (
	PermissionUserFederatedCredentialRead   = "user.federated_credential.read"
	PermissionUserFederatedCredentialWrite  = "user.federated_credential.write"
	PermissionUserFederatedCredentialDelete = "user.federated_credential.delete"
)

// FederatedCredentialKeySource says where the keys that verify the issuer's tokens come from.
type FederatedCredentialKeySource int32

const (
	FederatedCredentialKeySourceUnspecified FederatedCredentialKeySource = iota
	// FederatedCredentialKeySourceIssuerMetadata: the keys the issuer publishes, found through its
	// OpenID Provider metadata at MetadataURL.
	FederatedCredentialKeySourceIssuerMetadata
	// FederatedCredentialKeySourcePinnedKeys: the JSON Web Key Set stored on the credential; the
	// issuer's metadata is not fetched.
	FederatedCredentialKeySourcePinnedKeys
)

// FederatedCredentialAlgorithms are the signature algorithms a credential may allow. Anything else
// (none, the HMAC family, PS*, other curves) is refused.
var FederatedCredentialAlgorithms = []string{"ES256", "RS256", "EdDSA"}

// Limits of a federated credential.
const (
	federatedCredentialMaxTextLength   = 1024
	federatedCredentialMaxClaimLength  = 256
	federatedCredentialMaxConditions   = 20
	federatedCredentialMaxPinnedKeys   = 20
	federatedCredentialMaxPinnedLength = 64 * 1024
	federatedCredentialMinRSABits      = 2048
	// FederatedCredentialMaxTokenAge bounds how old a presented token may be allowed to be.
	FederatedCredentialMaxTokenAge = 24 * time.Hour
	// FederatedCredentialMaxTokenLifetime bounds the lifetime of the machine token a credential may
	// allow: the token is obtained again by a new exchange, never refreshed.
	FederatedCredentialMaxTokenLifetime = time.Hour
)

// federatedCredentialReservedClaims are checked by the exchange itself; a subject rule or a claim
// condition on one of them is refused.
var federatedCredentialReservedClaims = []string{"iss", "aud", "exp", "nbf", "iat", "jti"}

// FederatedCredentialSubjectRule names the claim that identifies the workload and the value it must
// have: either exactly Exact, or a match of Pattern. A pattern is an RE2 expression that is anchored
// at both ends (it must match the whole value) and must begin with literal text, so that no pattern
// can match every subject. The claim should be one the issuer never reassigns (an immutable ID
// rather than a name). Its value in the token must be a string.
//
// The JSON names are part of the stored events.
type FederatedCredentialSubjectRule struct {
	Claim   string `json:"claim"`
	Exact   string `json:"exact,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}

// FederatedCredentialClaimCondition requires a claim of the token to be a string equal to Value.
//
// The JSON names are part of the stored events.
type FederatedCredentialClaimCondition struct {
	Claim string `json:"claim"`
	Value string `json:"value"`
}

// FederatedCredential is the configuration of a federated credential of a machine user.
type FederatedCredential struct {
	// Issuer is compared exactly with the token's iss claim. It is an https URL.
	Issuer    string
	KeySource FederatedCredentialKeySource
	// PinnedKeys is a JSON Web Key Set of public keys, set only with
	// FederatedCredentialKeySourcePinnedKeys.
	PinnedKeys string
	// Algorithms the token may be signed with, a subset of FederatedCredentialAlgorithms.
	Algorithms []string
	// Audience the token's aud claim must contain.
	Audience        string
	SubjectRule     FederatedCredentialSubjectRule
	ClaimConditions []FederatedCredentialClaimCondition
	// MaxTokenAge is how long after its issue time (iat) a token is still accepted, even if it has
	// not expired.
	MaxTokenAge time.Duration
	// MaxTokenLifetime caps the lifetime of the machine token issued in exchange.
	MaxTokenLifetime time.Duration
	// Disabled credentials are kept but accept no token.
	Disabled bool
}

// Validate refuses a credential that is incomplete, that names an unsupported algorithm, whose
// issuer is not an https URL, or whose subject rule is empty or could match every subject.
func (c *FederatedCredential) Validate() error {
	if err := c.validateIssuer(); err != nil {
		return err
	}
	if err := c.validateAlgorithms(); err != nil {
		return err
	}
	if err := c.validateKeySource(); err != nil {
		return err
	}
	if c.Audience == "" {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc7aud", "Errors.User.Machine.FederatedCredential.AudienceMissing")
	}
	if !isFederatedCredentialText(c.Audience) || strings.ContainsFunc(c.Audience, unicode.IsSpace) {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc8aud", "Errors.User.Machine.FederatedCredential.AudienceInvalid")
	}
	if err := c.SubjectRule.validate(); err != nil {
		return err
	}
	if err := validateFederatedCredentialConditions(c.ClaimConditions); err != nil {
		return err
	}
	if c.MaxTokenAge <= 0 || c.MaxTokenAge > FederatedCredentialMaxTokenAge {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc1age", "Errors.User.Machine.FederatedCredential.MaxTokenAgeInvalid")
	}
	if c.MaxTokenLifetime <= 0 || c.MaxTokenLifetime > FederatedCredentialMaxTokenLifetime {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc1lft", "Errors.User.Machine.FederatedCredential.MaxTokenLifetimeInvalid")
	}
	return nil
}

func (c *FederatedCredential) validateIssuer() error {
	invalid := zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc2iss", "Errors.User.Machine.FederatedCredential.IssuerInvalid")
	if !strings.HasPrefix(c.Issuer, "https://") || !isFederatedCredentialText(c.Issuer) || strings.ContainsFunc(c.Issuer, unicode.IsSpace) {
		return invalid
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(c.Issuer, "#") {
		return invalid
	}
	return nil
}

func (c *FederatedCredential) validateAlgorithms() error {
	if len(c.Algorithms) == 0 {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc3alg", "Errors.User.Machine.FederatedCredential.AlgorithmsMissing")
	}
	for i, alg := range c.Algorithms {
		if !slices.Contains(FederatedCredentialAlgorithms, alg) || slices.Contains(c.Algorithms[:i], alg) {
			return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc4alg", "Errors.User.Machine.FederatedCredential.AlgorithmUnsupported")
		}
	}
	return nil
}

func (c *FederatedCredential) validateKeySource() error {
	switch c.KeySource {
	case FederatedCredentialKeySourceIssuerMetadata:
		if c.PinnedKeys != "" {
			return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc5key", "Errors.User.Machine.FederatedCredential.PinnedKeysInvalid")
		}
		// The metadata is fetched only from public addresses on the standard https port; an issuer
		// elsewhere can only be used with pinned keys.
		metadataURL, err := url.Parse(c.MetadataURL())
		if err != nil || publicfetch.CheckURL(metadataURL) != nil {
			return zerrors.ThrowInvalidArgument(err, "DOMAIN-Fc6key", "Errors.User.Machine.FederatedCredential.IssuerNotFetchable")
		}
		return nil
	case FederatedCredentialKeySourcePinnedKeys:
		_, err := c.PinnedKeySet()
		return err
	case FederatedCredentialKeySourceUnspecified:
		fallthrough
	default:
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc7key", "Errors.User.Machine.FederatedCredential.KeySourceMissing")
	}
}

// MetadataURL is the issuer's OpenID Provider metadata document: the issuer, without a trailing
// slash, followed by /.well-known/openid-configuration (OpenID Connect Discovery 1.0, section 4).
func (c *FederatedCredential) MetadataURL() string {
	return strings.TrimSuffix(c.Issuer, "/") + "/.well-known/openid-configuration"
}

// PinnedKeySet parses and checks the pinned keys: public signature keys only, each with a unique key
// ID and usable with at least one of the credential's algorithms (RSA of at least 2048 bits for
// RS256, P-256 for ES256, Ed25519 for EdDSA). The credential's algorithms must be valid already.
func (c *FederatedCredential) PinnedKeySet() (*jose.JSONWebKeySet, error) {
	invalid := func(parent error) error {
		return zerrors.ThrowInvalidArgument(parent, "DOMAIN-Fc8key", "Errors.User.Machine.FederatedCredential.PinnedKeysInvalid")
	}
	if c.PinnedKeys == "" || len(c.PinnedKeys) > federatedCredentialMaxPinnedLength {
		return nil, invalid(nil)
	}
	keySet := new(jose.JSONWebKeySet)
	if err := json.Unmarshal([]byte(c.PinnedKeys), keySet); err != nil {
		return nil, invalid(err)
	}
	if len(keySet.Keys) == 0 || len(keySet.Keys) > federatedCredentialMaxPinnedKeys {
		return nil, invalid(nil)
	}
	keyIDs := make([]string, 0, len(keySet.Keys))
	for _, key := range keySet.Keys {
		if key.KeyID == "" || slices.Contains(keyIDs, key.KeyID) || !key.Valid() || !key.IsPublic() {
			return nil, invalid(nil)
		}
		keyIDs = append(keyIDs, key.KeyID)
		if key.Use != "" && key.Use != "sig" {
			return nil, invalid(nil)
		}
		alg := federatedCredentialKeyAlgorithm(key.Key)
		if alg == "" || !slices.Contains(c.Algorithms, alg) || (key.Algorithm != "" && key.Algorithm != alg) {
			return nil, invalid(nil)
		}
	}
	return keySet, nil
}

// federatedCredentialKeyAlgorithm is the one allowed algorithm a public key can verify, or "".
func federatedCredentialKeyAlgorithm(key any) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() >= federatedCredentialMinRSABits {
			return "RS256"
		}
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return "ES256"
		}
	case ed25519.PublicKey:
		return "EdDSA"
	}
	return ""
}

func (r *FederatedCredentialSubjectRule) validate() error {
	if r.Claim == "" || (r.Exact == "") == (r.Pattern == "") {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc1sub", "Errors.User.Machine.FederatedCredential.SubjectRuleInvalid")
	}
	if !isFederatedCredentialClaim(r.Claim) {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc2sub", "Errors.User.Machine.FederatedCredential.ClaimInvalid")
	}
	if r.Exact != "" {
		if !isFederatedCredentialText(r.Exact) {
			return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc3sub", "Errors.User.Machine.FederatedCredential.SubjectRuleInvalid")
		}
		return nil
	}
	if !isFederatedCredentialText(r.Pattern) {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc4sub", "Errors.User.Machine.FederatedCredential.SubjectPatternInvalid")
	}
	// The pattern must stand on its own, so that wrapping it in anchors cannot change its meaning
	// (an unbalanced "a)|(b" would otherwise escape them).
	parsed, err := syntax.Parse(r.Pattern, syntax.Perl)
	if err != nil {
		return zerrors.ThrowInvalidArgument(err, "DOMAIN-Fc5sub", "Errors.User.Machine.FederatedCredential.SubjectPatternInvalid")
	}
	if _, err := r.compile(); err != nil {
		return zerrors.ThrowInvalidArgument(err, "DOMAIN-Fc6sub", "Errors.User.Machine.FederatedCredential.SubjectPatternInvalid")
	}
	if prefix, _ := literalPrefix(parsed.Simplify()); prefix == "" {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc7sub", "Errors.User.Machine.FederatedCredential.SubjectPatternTooBroad")
	}
	return nil
}

func (r *FederatedCredentialSubjectRule) compile() (*regexp.Regexp, error) {
	return regexp.Compile(`^(?:` + r.Pattern + `)$`)
}

// literalPrefix returns the literal, case-sensitive text every match of re begins with, and
// whether re matches exactly that text. Anything that is not a plain literal ends the prefix.
func literalPrefix(re *syntax.Regexp) (prefix string, complete bool) {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return "", false
		}
		return string(re.Rune), true
	case syntax.OpEmptyMatch, syntax.OpBeginText:
		return "", true
	case syntax.OpCapture:
		return literalPrefix(re.Sub[0])
	case syntax.OpConcat:
		var b strings.Builder
		for _, sub := range re.Sub {
			p, complete := literalPrefix(sub)
			b.WriteString(p)
			if !complete {
				return b.String(), false
			}
		}
		return b.String(), true
	default:
		return "", false
	}
}

// Matches reports whether value satisfies the rule. The rule must be valid.
func (r *FederatedCredentialSubjectRule) Matches(value string) bool {
	if value == "" {
		return false
	}
	if r.Exact != "" {
		return value == r.Exact
	}
	re, err := r.compile()
	return err == nil && r.Pattern != "" && re.MatchString(value)
}

// MatchesClaims reports whether a token's claims satisfy the subject rule and every claim
// condition. A claim that is missing or is not a string fails. Issuer, audience, algorithm, age and
// signature are not checked here.
func (c *FederatedCredential) MatchesClaims(claims map[string]any) bool {
	subject, ok := claims[c.SubjectRule.Claim].(string)
	if !ok || !c.SubjectRule.Matches(subject) {
		return false
	}
	for _, condition := range c.ClaimConditions {
		value, ok := claims[condition.Claim].(string)
		if !ok || value != condition.Value {
			return false
		}
	}
	return true
}

func validateFederatedCredentialConditions(conditions []FederatedCredentialClaimCondition) error {
	if len(conditions) > federatedCredentialMaxConditions {
		return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc1con", "Errors.User.Machine.FederatedCredential.ConditionInvalid")
	}
	for i, condition := range conditions {
		if !isFederatedCredentialClaim(condition.Claim) || condition.Value == "" || !isFederatedCredentialText(condition.Value) {
			return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc2con", "Errors.User.Machine.FederatedCredential.ConditionInvalid")
		}
		for _, earlier := range conditions[:i] {
			if earlier.Claim == condition.Claim {
				return zerrors.ThrowInvalidArgument(nil, "DOMAIN-Fc3con", "Errors.User.Machine.FederatedCredential.ConditionInvalid")
			}
		}
	}
	return nil
}

// isFederatedCredentialClaim accepts a top-level claim name that the exchange does not check by
// itself: printable, without white space, at most 256 bytes.
func isFederatedCredentialClaim(claim string) bool {
	return claim != "" && len(claim) <= federatedCredentialMaxClaimLength && utf8.ValidString(claim) &&
		!strings.ContainsFunc(claim, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) &&
		!slices.Contains(federatedCredentialReservedClaims, claim)
}

// isFederatedCredentialText accepts valid UTF-8 of at most 1024 bytes without control characters.
func isFederatedCredentialText(s string) bool {
	return len(s) <= federatedCredentialMaxTextLength && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}
