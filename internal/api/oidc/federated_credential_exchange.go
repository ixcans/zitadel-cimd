package oidc

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
)

// FederatedCredential is the Authentication Method Reference value (RFC 8176, section 2, which
// allows values outside its registry) of a session whose machine user was authenticated by a token
// of a foreign issuer that one of its federated credentials accepted
// (domain.UserAuthMethodTypeFederatedCredential). A session of a machine key has no value, so the
// two are told apart in the token's introspection and in an ID token.
const FederatedCredential = "federated_credential"

// federatedAssertionLeeway is the clock difference allowed between the issuer and this server when
// the expiration, not-before and issue times of an assertion are checked. It is not added to a
// credential's maximum token age.
const federatedAssertionLeeway = time.Minute

// federatedCredentialSignatureAlgorithms are the algorithms an assertion may be signed with at all;
// each credential allows a subset (domain.FederatedCredentialAlgorithms).
var federatedCredentialSignatureAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.RS256, jose.EdDSA}

// federatedCredentialExchanger decides, at the JWT-profile grant (RFC 7523), whether an assertion
// was signed by a foreign issuer for a federated credential of a machine user
// (domain.FederatedCredential), and if so, whether it is accepted and for which machine user.
//
// An assertion is for a federated credential when its iss claim is an https URL that the issuer of
// at least one enabled credential of the instance equals exactly. Every other assertion (one a
// machine user signed with its own key names the user as iss) is left to the grant's existing key
// path, unchanged.
type federatedCredentialExchanger struct {
	// credentials returns the enabled credentials of the instance whose issuer is exactly issuer,
	// with the read model brought up to date first.
	credentials func(ctx context.Context, issuer string) ([]*query.FederatedCredential, error)
	keys        *federatedIssuerKeys
	now         func() time.Time
}

func newFederatedCredentialExchanger(credentials func(ctx context.Context, issuer string) ([]*query.FederatedCredential, error), keys *federatedIssuerKeys) *federatedCredentialExchanger {
	return &federatedCredentialExchanger{
		credentials: credentials,
		keys:        keys,
		now:         time.Now,
	}
}

// federatedCredentialMatch is an accepted assertion: the credential that accepted it (the one with
// the smallest token lifetime cap, when several credentials of the same user accept it) and the
// exchange to record.
type federatedCredentialMatch struct {
	credential *query.FederatedCredential
	exchange   *domain.FederatedCredentialExchange
}

// match returns nil and no error when the assertion is not for a federated credential; the grant's
// existing key path then handles it as before. Otherwise it returns the match for exactly one
// machine user, or an invalid_grant error: no enabled credential of the issuer accepts the
// assertion, or the credentials of more than one machine user accept it.
//
// Single use is not decided here: the token's key goes into the session's push (see
// command.WithFederatedCredentialExchange), so it holds across server replicas.
func (e *federatedCredentialExchanger) match(ctx context.Context, assertion string) (_ *federatedCredentialMatch, err error) {
	if e == nil {
		return nil, nil
	}
	issuer, ok := federatedAssertionIssuer(assertion)
	if !ok {
		return nil, nil
	}
	credentials, err := e.credentials(ctx, issuer)
	if err != nil {
		return nil, err
	}
	if len(credentials) == 0 {
		return nil, nil
	}

	verified, err := e.verify(ctx, assertion, issuer, credentials)
	if err != nil {
		return nil, invalidFederatedAssertion(ctx, err, "assertion is not accepted by a federated credential")
	}
	userIDs := make([]string, 0, len(verified.accepted))
	for _, credential := range verified.accepted {
		if !slices.Contains(userIDs, credential.UserID) {
			userIDs = append(userIDs, credential.UserID)
		}
	}
	if len(userIDs) > 1 {
		// The patterns of credentials cannot be checked for overlap when they are written, so the
		// exchange refuses an assertion it could map to more than one machine user.
		return nil, invalidFederatedAssertion(ctx, nil, "assertion matches the federated credentials of more than one machine user")
	}
	credential := slices.MinFunc(verified.accepted, func(a, b *query.FederatedCredential) int {
		return cmp.Or(cmp.Compare(a.MaxTokenLifetime, b.MaxTokenLifetime), strings.Compare(a.ID, b.ID))
	})
	subjectValue, _ := verified.claims[credential.SubjectRule.Claim].(string)
	subject, _ := verified.claims["sub"].(string)
	return &federatedCredentialMatch{
		credential: credential,
		exchange: &domain.FederatedCredentialExchange{
			CredentialID:  credential.ID,
			UserID:        credential.UserID,
			ResourceOwner: credential.ResourceOwner,
			Issuer:        issuer,
			Subject:       subject,
			SubjectClaim:  credential.SubjectRule.Claim,
			SubjectValue:  subjectValue,
			TokenID:       verified.tokenID,
			AssertionKey:  domain.FederatedCredentialAssertionKey(issuer, verified.tokenID, verified.signingInput, verified.expiration),
		},
	}, nil
}

// verifiedFederatedAssertion is an assertion whose signature and claims satisfied at least one
// credential.
type verifiedFederatedAssertion struct {
	accepted     []*query.FederatedCredential
	claims       map[string]any
	tokenID      string
	signingInput string
	expiration   time.Time
}

// verify checks the assertion against every credential and returns those that accept it, or an
// error naming why the first credential refused it when none does. A credential accepts the
// assertion when it is enabled, its issuer equals iss exactly, the header's algorithm is one it
// allows and fits the key, the signature verifies with a key of its key source, the token is
// within its validity (exp, nbf) and no older than the credential's maximum age (iat), aud contains
// its audience, and the claims satisfy its subject rule and claim conditions.
func (e *federatedCredentialExchanger) verify(ctx context.Context, assertion, issuer string, credentials []*query.FederatedCredential) (*verifiedFederatedAssertion, error) {
	jws, err := jose.ParseSignedCompact(assertion, federatedCredentialSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("not a compact JWS signed with ES256, RS256 or EdDSA: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("not exactly one signature")
	}
	header := jws.Signatures[0].Protected
	claims, err := decodeFederatedClaims(jws.UnsafePayloadWithoutVerification())
	if err != nil {
		return nil, err
	}
	if iss, _ := claims["iss"].(string); iss != issuer {
		return nil, errors.New("issuer is not an exact match")
	}
	times, err := checkFederatedAssertionTimes(claims, e.now())
	if err != nil {
		return nil, err
	}
	tokenID, err := optionalStringClaim(claims, "jti")
	if err != nil {
		return nil, err
	}

	signingInput, err := canonicalSigningInput(assertion, jws)
	if err != nil {
		return nil, err
	}

	signatures := federatedSignatureCache{jws: jws, header: header, issuer: issuer, keys: e.keys}
	result := &verifiedFederatedAssertion{
		claims:       claims,
		tokenID:      tokenID,
		signingInput: signingInput,
		expiration:   times.expiration,
	}
	var firstRefusal error
	for _, credential := range credentials {
		if err := e.accepts(ctx, credential, issuer, header.Algorithm, claims, times, &signatures); err != nil {
			if firstRefusal == nil {
				firstRefusal = fmt.Errorf("credential %s: %w", credential.ID, err)
			}
			continue
		}
		result.accepted = append(result.accepted, credential)
	}
	if len(result.accepted) == 0 {
		return nil, firstRefusal
	}
	return result, nil
}

func (e *federatedCredentialExchanger) accepts(ctx context.Context, credential *query.FederatedCredential, issuer, algorithm string, claims map[string]any, times *federatedAssertionTimes, signatures *federatedSignatureCache) error {
	if credential.Disabled {
		return errors.New("credential disabled")
	}
	if credential.Issuer != issuer {
		return errors.New("issuer is not an exact match")
	}
	if !slices.Contains(credential.Algorithms, algorithm) {
		return fmt.Errorf("algorithm %q not allowed", algorithm)
	}
	if age := e.now().Sub(times.issuedAt); age > credential.MaxTokenAge {
		return fmt.Errorf("token issued %s ago, more than the maximum age of %s", age.Truncate(time.Second), credential.MaxTokenAge)
	}
	audience, err := audienceClaim(claims)
	if err != nil {
		return err
	}
	if !slices.Contains(audience, credential.Audience) {
		return errors.New("audience does not contain the credential's audience")
	}
	if !credential.MatchesClaims(claims) {
		return errors.New("subject rule or claim conditions not satisfied")
	}
	// The signature last: it may need a fetch of the issuer's keys, which a token that no
	// credential's claims accept does not get to cause.
	return signatures.verify(ctx, &credential.FederatedCredential, algorithm)
}

// federatedSignatureCache verifies the assertion's signature once per key source: once with the
// keys the issuer publishes, and once per distinct set of pinned keys.
type federatedSignatureCache struct {
	jws    *jose.JSONWebSignature
	header jose.Header
	issuer string
	keys   *federatedIssuerKeys

	issuerKeyResult *federatedSignatureResult
	pinnedResults   map[string]*federatedSignatureResult
}

type federatedSignatureResult struct {
	// algorithm is the one algorithm the verifying key can verify.
	algorithm string
	err       error
}

func (c *federatedSignatureCache) verify(ctx context.Context, credential *domain.FederatedCredential, algorithm string) error {
	var result *federatedSignatureResult
	switch credential.KeySource {
	case domain.FederatedCredentialKeySourceIssuerMetadata:
		if c.issuerKeyResult == nil {
			key, err := c.keys.key(ctx, c.issuer, c.header.KeyID)
			c.issuerKeyResult = c.verifyWith(key, err)
		}
		result = c.issuerKeyResult
	case domain.FederatedCredentialKeySourcePinnedKeys:
		if c.pinnedResults == nil {
			c.pinnedResults = make(map[string]*federatedSignatureResult)
		}
		var ok bool
		if result, ok = c.pinnedResults[credential.PinnedKeys]; !ok {
			result = c.verifyWith(pinnedFederatedKey(credential, c.header.KeyID))
			c.pinnedResults[credential.PinnedKeys] = result
		}
	case domain.FederatedCredentialKeySourceUnspecified:
		fallthrough
	default:
		return errors.New("credential has no key source")
	}
	if result.err != nil {
		return result.err
	}
	if result.algorithm != algorithm {
		return fmt.Errorf("algorithm %q does not fit the key", algorithm)
	}
	return nil
}

func (c *federatedSignatureCache) verifyWith(key *jose.JSONWebKey, err error) *federatedSignatureResult {
	if err != nil {
		return &federatedSignatureResult{err: err}
	}
	if !usableFederatedKey(key) {
		return &federatedSignatureResult{err: errors.New("the key is not a usable signature key")}
	}
	if _, err := c.jws.Verify(key); err != nil {
		return &federatedSignatureResult{err: fmt.Errorf("signature: %w", err)}
	}
	return &federatedSignatureResult{algorithm: domain.FederatedCredentialKeyAlgorithm(key.Key)}
}

func pinnedFederatedKey(credential *domain.FederatedCredential, keyID string) (*jose.JSONWebKey, error) {
	keySet, err := credential.PinnedKeySet()
	if err != nil {
		return nil, err
	}
	if key := findFederatedKey(keySet.Keys, keyID); key != nil {
		return key, nil
	}
	return nil, errFederatedKeyUnknown
}

// canonicalSigningInput is the signing input of the assertion as its issuer signed it: the decoded
// header and payload, each encoded again in canonical base64url. The decoder accepts other
// spellings of the same bytes (line breaks, non-zero unused bits in the last character), and the
// signature is checked against the canonical form, so a token's single-use key is derived from it
// and not from the string as presented.
func canonicalSigningInput(assertion string, jws *jose.JSONWebSignature) (string, error) {
	protected, _, _ := strings.Cut(assertion, ".")
	header, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(jws.UnsafePayloadWithoutVerification()), nil
}

// federatedAssertionIssuer reads the iss claim of an assertion without verifying anything, to
// decide whether it is for a federated credential. It reports false for anything that is not a
// compact JWS whose payload names an https issuer of a sensible length.
func federatedAssertionIssuer(assertion string) (string, bool) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	if !strings.HasPrefix(claims.Issuer, "https://") || len(claims.Issuer) > 1024 {
		return "", false
	}
	return claims.Issuer, true
}

func decodeFederatedClaims(payload []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	claims := make(map[string]any)
	if err := decoder.Decode(&claims); err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("claims: trailing data")
	}
	return claims, nil
}

type federatedAssertionTimes struct {
	expiration time.Time
	issuedAt   time.Time
}

// checkFederatedAssertionTimes requires exp and iat, both numeric dates: the token must not have
// expired, must not be valid only later (nbf, when present), and must not have been issued in the
// future. The maximum age is the credential's and is checked per credential.
func checkFederatedAssertionTimes(claims map[string]any, now time.Time) (*federatedAssertionTimes, error) {
	expiration, ok, err := numericDateClaim(claims, "exp")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("exp missing")
	}
	if !now.Before(expiration.Add(federatedAssertionLeeway)) {
		return nil, errors.New("token expired")
	}
	notBefore, ok, err := numericDateClaim(claims, "nbf")
	if err != nil {
		return nil, err
	}
	if ok && now.Add(federatedAssertionLeeway).Before(notBefore) {
		return nil, errors.New("token not valid yet")
	}
	issuedAt, ok, err := numericDateClaim(claims, "iat")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("iat missing: the token's age cannot be checked")
	}
	if now.Add(federatedAssertionLeeway).Before(issuedAt) {
		return nil, errors.New("iat in the future")
	}
	return &federatedAssertionTimes{expiration: expiration, issuedAt: issuedAt}, nil
}

// numericDateClaim reads a NumericDate (RFC 7519, section 2): a JSON number of seconds since the
// epoch, fractions allowed. Anything else under the name is an error.
func numericDateClaim(claims map[string]any, name string) (time.Time, bool, error) {
	value, ok := claims[name]
	if !ok {
		return time.Time{}, false, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return time.Time{}, false, fmt.Errorf("%s is not a number", name)
	}
	seconds, err := number.Float64()
	if err != nil || math.IsNaN(seconds) || seconds < 0 || seconds > 1e11 {
		return time.Time{}, false, fmt.Errorf("%s is not a usable date", name)
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*1e9)), true, nil
}

func optionalStringClaim(claims map[string]any, name string) (string, error) {
	value, ok := claims[name]
	if !ok {
		return "", nil
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s is not a string", name)
	}
	return s, nil
}

// audienceClaim reads aud, a string or an array of strings (RFC 7519, section 4.1.3).
func audienceClaim(claims map[string]any) ([]string, error) {
	switch aud := claims["aud"].(type) {
	case string:
		return []string{aud}, nil
	case []any:
		audience := make([]string, 0, len(aud))
		for _, entry := range aud {
			s, ok := entry.(string)
			if !ok {
				return nil, errors.New("aud contains a value that is not a string")
			}
			audience = append(audience, s)
		}
		return audience, nil
	default:
		return nil, errors.New("aud missing or not a string or array of strings")
	}
}

func invalidFederatedAssertion(ctx context.Context, parent error, description string) error {
	return oidc.ErrInvalidGrant().WithParent(parent).WithReturnParentToClient(authz.GetFeatures(ctx).DebugOIDCParentError).WithDescription("%s", description)
}
