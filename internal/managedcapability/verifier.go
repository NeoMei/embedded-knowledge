// Package managedcapability verifies a signed, task-bound knowledge capability.
// It is deliberately not connected to HTTP handlers, workers, or providers.
// Verification alone does not authorize a charge: callers must establish the
// expected binding from trusted server-side state, check revocation and enforce
// durable one-work/one-grant ownership before using a managed model.
package managedcapability

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

const EmbeddingModel = "unihub-text-embedding-v4"
const EmbeddingSpace = "aliyun/text-embedding-v4/v4/1024/text"
const EmbeddingDimensions = 1024

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
	// InputDigest must be a domain-separated keyed MAC of the document, not
	// an ordinary hash: signed capabilities are visible to their bearer.
	InputDigest    string `json:"input_digest"`
	EmbeddingModel string `json:"embedding_model"`
	EmbeddingSpace string `json:"embedding_space"`
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
	return b.TenantID != 0 && identifier.MatchString(b.ActorID) && identifier.MatchString(b.AccountID) && identifier.MatchString(b.TaskID) && identifier.MatchString(b.WorkID) && identifier.MatchString(b.GrantID) && identifier.MatchString(b.KnowledgeBaseID) && identifier.MatchString(b.KnowledgeID) && b.Purpose == "document-ingest" && digest.MatchString(b.InputDigest) && b.EmbeddingModel == EmbeddingModel && b.EmbeddingSpace == EmbeddingSpace
}

// ActiveClaims is a short-lived, nonce-bound assertion of current access.
type ActiveClaims struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	Binding
	Nonce     string `json:"nonce"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// verifyEnvelope rejects duplicate members and non-canonical encodings before
// accepting a signature from the configured host trust set.
func (v *Verifier) verifyEnvelope(token, kind string, out any) error {
	if v == nil || len(token) > 16384 {
		return ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != kind || !keyID.MatchString(parts[1]) {
		return ErrInvalid
	}
	key, ok := v.keys[parts[1]]
	if !ok {
		return ErrInvalid
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
		return ErrInvalid
	}
	data, err := decode(parts[2])
	if err != nil || len(data) > 8192 {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ErrInvalid
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return ErrInvalid
		}
		seen[name] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return ErrInvalid
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return ErrInvalid
	}
	return nil
}

// Verify checks a domain-separated signature and exact trusted binding. A token
// can be verified repeatedly for recovery; replay and revocation enforcement
// require the durable admission/journal transaction outside this verifier.
func (v *Verifier) Verify(token string, expected Binding) (Claims, error) {
	var claims Claims
	if !validBinding(expected) || v.verifyEnvelope(token, "weknora-cap-v1", &claims) != nil || claims.Issuer != v.issuer || claims.Audience != v.audience || !validBinding(claims.Binding) || claims.Binding != expected {
		return Claims{}, ErrInvalid
	}
	now := v.now().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now || claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > int64(v.lifetime/time.Second) {
		return Claims{}, ErrInvalid
	}
	return claims, nil
}

// VerifyActive accepts a fresh response only for the independently generated
// nonce and exact saved binding; the caller must discard a used nonce.
func (v *Verifier) VerifyActive(token string, expected Binding, nonce string) (ActiveClaims, error) {
	var claims ActiveClaims
	if !validBinding(expected) || !digest.MatchString(nonce) || v.verifyEnvelope(token, "weknora-auth-v1", &claims) != nil || claims.Issuer != v.issuer || claims.Audience != v.audience || claims.Binding != expected || claims.Nonce != nonce {
		return ActiveClaims{}, ErrInvalid
	}
	now := v.now().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now || claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 30 {
		return ActiveClaims{}, ErrInvalid
	}
	return claims, nil
}

type SnapshotClaims struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	Binding
	Nonce         string `json:"nonce"`
	IssuedAt      int64  `json:"issued_at"`
	ExpiresAt     int64  `json:"expires_at"`
	ContentSHA256 string `json:"content_sha256"`
}

func (v *Verifier) VerifySnapshot(token string, expected Binding, nonce string, content []byte) (SnapshotClaims, error) {
	var claims SnapshotClaims
	if !validBinding(expected) || !digest.MatchString(nonce) || len(content) == 0 || len(content) > 8<<20 || v.verifyEnvelope(token, "weknora-snapshot-v1", &claims) != nil || claims.Issuer != v.issuer || claims.Audience != v.audience || claims.Binding != expected || claims.Nonce != nonce || !digest.MatchString(claims.ContentSHA256) {
		return SnapshotClaims{}, ErrInvalid
	}
	sum := sha256.Sum256(content)
	if !hmac.Equal([]byte(claims.ContentSHA256), []byte(hex.EncodeToString(sum[:]))) {
		return SnapshotClaims{}, ErrInvalid
	}
	now := v.now().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now || claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 30 {
		return SnapshotClaims{}, ErrInvalid
	}
	return claims, nil
}

type ResultClaims struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	Binding
	Nonce         string `json:"nonce"`
	IssuedAt      int64  `json:"issued_at"`
	ExpiresAt     int64  `json:"expires_at"`
	CallID        string `json:"call_id"`
	Model         string `json:"model"`
	Operation     string `json:"operation"`
	WireOperation string `json:"wire_operation"`
	Status        string `json:"status"`
	ContentSHA256 string `json:"content_sha256"`
}

func (v *Verifier) VerifyResult(token string, expected Binding, nonce, callID, model, operation, wire string, content []byte) (ResultClaims, error) {
	var claims ResultClaims
	if !validBinding(expected) || !digest.MatchString(nonce) || !identifier.MatchString(callID) || !identifier.MatchString(model) || !identifier.MatchString(operation) || !identifier.MatchString(wire) || len(content) == 0 || len(content) > 16<<20 || v.verifyEnvelope(token, "weknora-result-v1", &claims) != nil || claims.Issuer != v.issuer || claims.Audience != v.audience || claims.Binding != expected || claims.Nonce != nonce || claims.CallID != callID || claims.Model != model || claims.Operation != operation || claims.WireOperation != wire || claims.Status != "SETTLED" || !digest.MatchString(claims.ContentSHA256) {
		return ResultClaims{}, ErrInvalid
	}
	sum := sha256.Sum256(content)
	if !hmac.Equal([]byte(claims.ContentSHA256), []byte(hex.EncodeToString(sum[:]))) {
		return ResultClaims{}, ErrInvalid
	}
	now := v.now().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now || claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 30 {
		return ResultClaims{}, ErrInvalid
	}
	return claims, nil
}

// DecodeVerified obtains a proposed binding from the signed envelope only after
// signature/format validation. Callers must still independently establish live
// authority and compare it against trusted tenant, KB and document state.
func (v *Verifier) DecodeVerified(token string) (Claims, error) {
	var proposed Claims
	if v.verifyEnvelope(token, "weknora-cap-v1", &proposed) != nil {
		return Claims{}, ErrInvalid
	}
	return v.Verify(token, proposed.Binding)
}
