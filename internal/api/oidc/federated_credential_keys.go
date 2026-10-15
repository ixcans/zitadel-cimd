package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/zitadel/zitadel/internal/domain"
)

const (
	// federatedIssuerKeysTTL is how long the keys fetched from an issuer are used before they are
	// fetched again. A key the issuer withdraws is trusted at most this long after the withdrawal.
	federatedIssuerKeysTTL = 15 * time.Minute
	// federatedIssuerKeysRefetchInterval is the shortest time between two fetches for one issuer.
	// A token naming a key the cache does not hold causes a fetch (the issuer may have rotated its
	// keys), but not more often than this, so that tokens with made-up key IDs cannot make the
	// server fetch again and again.
	federatedIssuerKeysRefetchInterval = time.Minute
	// federatedIssuerFetchTimeout bounds the fetch of the metadata and the key set together.
	federatedIssuerFetchTimeout = 10 * time.Second
	// federatedIssuerMaxBodyBytes bounds each document read from an issuer.
	federatedIssuerMaxBodyBytes = 256 * 1024
	// federatedIssuerMaxKeys bounds how many keys of a key set are kept.
	federatedIssuerMaxKeys = 100
)

var (
	errFederatedKeyUnknown      = errors.New("the issuer publishes no usable key with this key ID")
	errFederatedKeysUnavailable = errors.New("the issuer's keys could not be fetched")
)

// federatedIssuerKeys caches the signature keys of the issuers of federated credentials, fetched
// from each issuer's OpenID Provider metadata (OpenID Connect Discovery 1.0) and the key set its
// jwks_uri names. Keys are public, so one cache serves every instance.
//
// The keys of an issuer are fetched when none are cached, when the cached ones are older than
// federatedIssuerKeysTTL, and when a token names a key ID the cached set lacks, so a rotated key
// is picked up without anyone pasting keys; fetches for one issuer are at least
// federatedIssuerKeysRefetchInterval apart. When a fetch fails, keys older than the TTL are not
// used: the exchange fails closed.
type federatedIssuerKeys struct {
	// httpClient fetches the documents. In production it is publicfetch.NewClient(): https on the
	// standard port to public unicast addresses only, no redirects.
	httpClient      *http.Client
	now             func() time.Time
	ttl             time.Duration
	refetchInterval time.Duration

	mu      sync.Mutex
	issuers map[string]*federatedIssuerKeySet
}

type federatedIssuerKeySet struct {
	// mu serializes the lookups and fetches of one issuer, so concurrent requests wait for one fetch.
	mu        sync.Mutex
	keys      []jose.JSONWebKey
	fetchedAt time.Time
	lastFetch time.Time
}

func newFederatedIssuerKeys(httpClient *http.Client) *federatedIssuerKeys {
	return &federatedIssuerKeys{
		httpClient:      httpClient,
		now:             time.Now,
		ttl:             federatedIssuerKeysTTL,
		refetchInterval: federatedIssuerKeysRefetchInterval,
		issuers:         make(map[string]*federatedIssuerKeySet),
	}
}

// key returns the key of issuer with keyID (any key ID when the set holds a single key and keyID
// is empty).
func (k *federatedIssuerKeys) key(ctx context.Context, issuer, keyID string) (*jose.JSONWebKey, error) {
	set := k.issuerSet(issuer)
	set.mu.Lock()
	defer set.mu.Unlock()

	now := k.now()
	fresh := set.keys != nil && now.Sub(set.fetchedAt) < k.ttl
	if fresh {
		if key := findFederatedKey(set.keys, keyID); key != nil {
			return key, nil
		}
	}
	if !set.lastFetch.IsZero() && now.Sub(set.lastFetch) < k.refetchInterval {
		if fresh {
			return nil, errFederatedKeyUnknown
		}
		return nil, errFederatedKeysUnavailable
	}
	set.lastFetch = now
	keys, err := k.fetch(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFederatedKeysUnavailable, err)
	}
	set.keys, set.fetchedAt = keys, now
	if key := findFederatedKey(set.keys, keyID); key != nil {
		return key, nil
	}
	return nil, errFederatedKeyUnknown
}

func (k *federatedIssuerKeys) issuerSet(issuer string) *federatedIssuerKeySet {
	k.mu.Lock()
	defer k.mu.Unlock()
	set, ok := k.issuers[issuer]
	if !ok {
		set = new(federatedIssuerKeySet)
		k.issuers[issuer] = set
	}
	return set
}

// fetch reads the issuer's metadata, checks that it names the issuer exactly (OpenID Connect
// Discovery 1.0, section 4.3), and reads the key set its jwks_uri names. It keeps the public
// signature keys an allowed algorithm can verify and skips every other key.
func (k *federatedIssuerKeys) fetch(ctx context.Context, issuer string) ([]jose.JSONWebKey, error) {
	ctx, cancel := context.WithTimeout(ctx, federatedIssuerFetchTimeout)
	defer cancel()

	var metadata struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := k.getJSON(ctx, (&domain.FederatedCredential{Issuer: issuer}).MetadataURL(), &metadata); err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	if metadata.Issuer != issuer {
		return nil, errors.New("metadata: the issuer it names is not the token's issuer")
	}
	jwksURI, err := url.Parse(metadata.JWKSURI)
	if err != nil || jwksURI.Scheme != "https" || jwksURI.Host == "" {
		return nil, errors.New("metadata: jwks_uri is not an https url")
	}
	var keySet struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := k.getJSON(ctx, jwksURI.String(), &keySet); err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	keys := make([]jose.JSONWebKey, 0, len(keySet.Keys))
	for _, raw := range keySet.Keys {
		if len(keys) == federatedIssuerMaxKeys {
			break
		}
		var key jose.JSONWebKey
		// A key of a type this server does not support is skipped, not fatal: a key set may carry
		// keys for other uses.
		if err := key.UnmarshalJSON(raw); err != nil {
			continue
		}
		if usableFederatedKey(&key) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (k *federatedIssuerKeys) getJSON(ctx context.Context, target string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, federatedIssuerMaxBodyBytes+1))
	if err != nil {
		return err
	}
	if len(body) > federatedIssuerMaxBodyBytes {
		return errors.New("document too large")
	}
	return json.Unmarshal(body, v)
}

// usableFederatedKey accepts a public signature key that one of the allowed algorithms can verify,
// whose own alg, if it names one, is that algorithm.
func usableFederatedKey(key *jose.JSONWebKey) bool {
	if !key.Valid() || !key.IsPublic() || (key.Use != "" && key.Use != "sig") {
		return false
	}
	alg := domain.FederatedCredentialKeyAlgorithm(key.Key)
	return alg != "" && (key.Algorithm == "" || key.Algorithm == alg)
}

// findFederatedKey returns the key with keyID, or the only key when keyID is empty.
func findFederatedKey(keys []jose.JSONWebKey, keyID string) *jose.JSONWebKey {
	if keyID == "" {
		if len(keys) == 1 {
			return &keys[0]
		}
		return nil
	}
	for i := range keys {
		if keys[i].KeyID == keyID {
			return &keys[i]
		}
	}
	return nil
}
