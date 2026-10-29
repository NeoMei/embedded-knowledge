// Package managedcapability verifies a signed, task-bound knowledge capability.
// It is deliberately not connected to HTTP handlers, workers, or providers.
// Verification alone does not authorize a charge: callers must establish the
// expected binding from trusted server-side state, check revocation and enforce
// durable one-work/one-grant ownership before using a managed model.
package managedcapability

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("managed capability invalid")

var identifier = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,200}$`)
var keyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Binding is meaningful only when constructed from a trusted server-side
// admission and persisted work record, not from the submitted capability.
type Binding struct {
	TenantID        uint64 `json:"tenant_id"`
	ActorID         string `json:"actor_id"`
	AccountID       string `json:"account_id"`
	TaskID          string `json:"task_id"`
	WorkID          string `json:"work_id"`
	GrantID         string `json:"grant_id"`
	KnowledgeBaseID string `json:"knowledge_base_id"`
	KnowledgeID     string `json:"knowledge_id"`
	Purpose         string `json:"purpose"`
	InputDigest     string `json:"input_digest"`
}

type Claims struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	Binding
	IssuedAt  int64 `json:"issued_at"`
	ExpiresAt int64 `json:"expires_at"`
}

type Verifier struct {
	issuer, audience string
	keys             map[string]ed25519.PublicKey
	lifetime         time.Duration
	now              func() time.Time
}

// NewVerifier copies the trust set. Rotate by constructing a replacement with
// both old and new public keys during the overlap; remove an old key only after
// all its capabilities expire or are revoked. Issuing keys must not be present
// in the worker. A separate revocation check remains mandatory before billing.
func NewVerifier(issuer, audience string, keys map[string]ed25519.PublicKey, lifetime time.Duration, now func() time.Time) (*Verifier, error) {
	if issuer == "" || len(issuer) > 512 || strings.TrimSpace(issuer) != issuer || strings.ContainsAny(issuer, "\x00\r\n\t") || !identifier.MatchString(audience) || len(keys) == 0 || len(keys) > 8 || lifetime < time.Second || lifetime > 24*time.Hour || lifetime%time.Second != 0 || now == nil {
		return nil, ErrInvalid
	}
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		if !keyID.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		copied[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &Verifier{issuer: issuer, audience: audience, keys: copied, lifetime: lifetime, now: now}, nil
}

func validBinding(b Binding) bool {
	return b.TenantID != 0 && identifier.MatchString(b.ActorID) && identifier.MatchString(b.AccountID) && identifier.MatchString(b.TaskID) && identifier.MatchString(b.WorkID) && identifier.MatchString(b.GrantID) && identifier.MatchString(b.KnowledgeBaseID) && identifier.MatchString(b.KnowledgeID) && b.Purpose == "document-ingest" && digest.MatchString(b.InputDigest)
}

// Verify checks a domain-separated signature and exact trusted binding. A token
// can be verified repeatedly for recovery; replay and revocation enforcement
// require the durable admission/journal transaction outside this verifier.
func (v *Verifier) Verify(token string, expected Binding) (Claims, error) {
	var zero Claims
	if v == nil || !validBinding(expected) || len(token) > 16384 {
		return zero, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "weknora-cap-v1" || !keyID.MatchString(parts[1]) {
		return zero, ErrInvalid
	}
	key, ok := v.keys[parts[1]]
	if !ok {
		return zero, ErrInvalid
	}
	decode := func(value string) ([]byte, error) {
		b, e := base64.RawURLEncoding.DecodeString(value)
		if e != nil || base64.RawURLEncoding.EncodeToString(b) != value {
			return nil, ErrInvalid
		}
		return b, nil
	}
	sig, err := decode(parts[3])
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, []byte(strings.Join(parts[:3], ".")), sig) {
		return zero, ErrInvalid
	}
	data, err := decode(parts[2])
	if err != nil || len(data) > 8192 {
		return zero, ErrInvalid
	}
	// encoding/json accepts duplicate members. Reject them before decoding so
	// another implementation cannot interpret a signed identity differently.
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return zero, ErrInvalid
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return zero, ErrInvalid
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return zero, ErrInvalid
		}
		seen[name] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return zero, ErrInvalid
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return zero, ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return zero, ErrInvalid
	}
	var claims Claims
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claims) != nil || claims.Issuer != v.issuer || claims.Audience != v.audience || !validBinding(claims.Binding) || claims.Binding != expected {
		return zero, ErrInvalid
	}
	now := v.now().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now || claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > int64(v.lifetime/time.Second) {
		return zero, ErrInvalid
	}
	return claims, nil
}
