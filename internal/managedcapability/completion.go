package managedcapability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// IndexBinding is immutable storage and route provenance. Empty fields are
// accepted only by the old envelope decoder; durable worker admission requires
// ValidIndexBinding and never upgrades legacy registrations implicitly.
type IndexBinding struct {
	NamespaceID           string `json:"namespace_id,omitempty"`
	StorageID             string `json:"storage_id,omitempty"`
	StorageGeneration     string `json:"storage_generation,omitempty"`
	EmbeddingPolicyDigest string `json:"embedding_policy_digest,omitempty"`
	OpaquePin             string `json:"opaque_pin,omitempty"`
	RouteGeneration       string `json:"route_generation,omitempty"`
	IndexRevision         int64  `json:"index_revision,omitempty"`
}

func ValidIndexBinding(b IndexBinding) bool {
	return digest.MatchString(b.NamespaceID) && digest.MatchString(b.StorageID) && digest.MatchString(b.StorageGeneration) && digest.MatchString(b.EmbeddingPolicyDigest) && digest.MatchString(b.OpaquePin) && digest.MatchString(b.RouteGeneration) && b.IndexRevision > 0
}
func validOptionalIndex(b IndexBinding) bool { return b == (IndexBinding{}) || ValidIndexBinding(b) }

// CompletedUse has no grant, task credential, or paid dispatch permission.
// The envelope kind is completed-index-use-v1. The ordinary request proof
// separately binds its exact HTTP body, path and one-use nonce.
type CompletedUse struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	NamespaceID       string `json:"namespace_id"`
	TenantID          uint64 `json:"tenant_id"`
	ActorID           string `json:"actor_id"`
	AccountID         string `json:"account_id"`
	KnowledgeBaseID   string `json:"knowledge_base_id"`
	KnowledgeID       string `json:"knowledge_id"`
	WorkID            string `json:"work_id"`
	StorageID         string `json:"storage_id"`
	StorageGeneration string `json:"storage_generation"`
	IndexRevision     int64  `json:"index_revision"`
	CompletionDigest  string `json:"completion_digest"`
	HostBootID        string `json:"host_boot_id"`
	WorkerBootID      string `json:"worker_boot_id"`
	IssuedAt          int64  `json:"issued_at"`
	ExpiresAt         int64  `json:"expires_at"`
}

func (v *Verifier) ValidCompletedUse(c CompletedUse) bool {
	return c.Version == "completed-index-use-v1" && c.Purpose == "completed_index_read" && digest.MatchString(c.NamespaceID) && c.TenantID != 0 && identifier.MatchString(c.ActorID) && identifier.MatchString(c.AccountID) && identifier.MatchString(c.KnowledgeBaseID) && identifier.MatchString(c.KnowledgeID) && identifier.MatchString(c.WorkID) && digest.MatchString(c.StorageID) && digest.MatchString(c.StorageGeneration) && c.IndexRevision > 0 && digest.MatchString(c.CompletionDigest) && digest.MatchString(c.HostBootID) && digest.MatchString(c.WorkerBootID) && v.validWindow(c.IssuedAt, c.ExpiresAt, 30)
}
func (v *Verifier) DecodeCompletedUse(token string) (CompletedUse, error) {
	var c CompletedUse
	if v.verifyEnvelope(token, "completed-index-use-v1", &c) != nil || !v.ValidCompletedUse(c) {
		return c, ErrInvalid
	}
	return c, nil
}

type StorageRequest struct {
	Version         string `json:"version"`
	NamespaceID     string `json:"namespace_id"`
	TenantID        uint64 `json:"tenant_id"`
	ActorID         string `json:"actor_id"`
	AccountID       string `json:"account_id"`
	KnowledgeBaseID string `json:"knowledge_base_id"`
	WorkID          string `json:"work_id"`
	HostBootID      string `json:"host_boot_id"`
	IssuedAt        int64  `json:"issued_at"`
	ExpiresAt       int64  `json:"expires_at"`
}

func (v *Verifier) DecodeStorageRequest(token string) (StorageRequest, error) {
	var c StorageRequest
	if v.verifyEnvelope(token, "managed-storage-v1", &c) != nil || c.Version != "managed-storage-v1" || !digest.MatchString(c.NamespaceID) || c.TenantID == 0 || !identifier.MatchString(c.ActorID) || !identifier.MatchString(c.AccountID) || !identifier.MatchString(c.KnowledgeBaseID) || !identifier.MatchString(c.WorkID) || !digest.MatchString(c.HostBootID) || !v.validWindow(c.IssuedAt, c.ExpiresAt, 30) {
		return c, ErrInvalid
	}
	return c, nil
}

// Discovery permits recovery only against the host's already durable PENDING
// intent, which includes this exact immutable producer binding and snapshot.
type CompletionDiscover struct {
	Version        string  `json:"version"`
	Purpose        string  `json:"purpose"`
	Binding        Binding `json:"binding"`
	SnapshotSHA256 string  `json:"snapshot_sha256"`
	HostBootID     string  `json:"host_boot_id"`
	WorkerBootID   string  `json:"worker_boot_id"`
	IssuedAt       int64   `json:"issued_at"`
	ExpiresAt      int64   `json:"expires_at"`
}

func (v *Verifier) DecodeCompletionDiscover(token string) (CompletionDiscover, error) {
	var c CompletionDiscover
	if v.verifyEnvelope(token, "completed-index-discover-v1", &c) != nil || c.Version != "completed-index-discover-v1" || c.Purpose != "completion_discover" || !validBinding(c.Binding) || !ValidIndexBinding(c.Binding.IndexBinding) || !digest.MatchString(c.SnapshotSHA256) || !digest.MatchString(c.HostBootID) || !digest.MatchString(c.WorkerBootID) || !v.validWindow(c.IssuedAt, c.ExpiresAt, 30) {
		return c, ErrInvalid
	}
	return c, nil
}

// StrictJSON rejects duplicate fields at every depth, unknown fields and tails.
func StrictJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func() error
	value = func() error {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := t.(string)
				if !ok || seen[s] {
					return ErrInvalid
				}
				seen[s] = true
				if e = value(); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := value(); e != nil {
					return e
				}
			}
		default:
			return ErrInvalid
		}
		_, err = d.Token()
		return err
	}
	if value() != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	return nil
}

// checkLocalRead is independent of the historical ingest token and journal.
// The current host must sign the exact scope and fresh worker challenge after
// checking current actor authority and its durable intent/completion anchor.
func (h *HostAuthority) checkLocalRead(ctx context.Context, path, kind string, scope any) error {
	if h == nil {
		return ErrInvalid
	}
	var n [32]byte
	if _, err := rand.Read(n[:]); err != nil {
		return ErrInvalid
	}
	nonce := hex.EncodeToString(n[:])
	rawScope, err := json.Marshal(scope)
	if err != nil {
		return ErrInvalid
	}
	body, err := json.Marshal(struct {
		Nonce string          `json:"nonce"`
		Scope json.RawMessage `json:"scope"`
	}{nonce, rawScope})
	if err != nil {
		return ErrInvalid
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimSuffix(h.endpoint, "/authorize")+path, bytes.NewReader(body))
	if err != nil {
		return ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.do(req, body)
	if err != nil {
		return ErrInvalid
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return ErrInvalid
	}
	var result struct {
		Assertion string `json:"assertion"`
	}
	if StrictJSON(raw, &result) != nil {
		return ErrInvalid
	}
	var assertion struct {
		Scope     json.RawMessage `json:"scope"`
		Nonce     string          `json:"nonce"`
		IssuedAt  int64           `json:"issued_at"`
		ExpiresAt int64           `json:"expires_at"`
	}
	if h.verifier.verifyEnvelope(result.Assertion, kind, &assertion) != nil || assertion.Nonce != nonce || !h.verifier.validWindow(assertion.IssuedAt, assertion.ExpiresAt, 30) {
		return ErrInvalid
	}
	// Re-encode into the typed request: whitespace is immaterial; all fields and
	// types are exact and duplicate/unknown fields are refused.
	if kind == "completed-index-auth-v1" {
		var c CompletedUse
		if StrictJSON(assertion.Scope, &c) != nil {
			return ErrInvalid
		}
		a, _ := json.Marshal(c)
		if !bytes.Equal(a, rawScope) {
			return ErrInvalid
		}
	} else if kind == "completed-index-discover-auth-v1" {
		var c CompletionDiscover
		if StrictJSON(assertion.Scope, &c) != nil {
			return ErrInvalid
		}
		a, _ := json.Marshal(c)
		if !bytes.Equal(a, rawScope) {
			return ErrInvalid
		}
	} else {
		var c StorageRequest
		if StrictJSON(assertion.Scope, &c) != nil {
			return ErrInvalid
		}
		a, _ := json.Marshal(c)
		if !bytes.Equal(a, rawScope) {
			return ErrInvalid
		}
	}
	return ctx.Err()
}
func (h *HostAuthority) CompletedCheck(ctx context.Context, c CompletedUse) error {
	if !h.verifier.ValidCompletedUse(c) {
		return ErrInvalid
	}
	return h.checkLocalRead(ctx, "/completed-authorize", "completed-index-auth-v1", c)
}
func (h *HostAuthority) StorageCheck(ctx context.Context, c StorageRequest) error {
	return h.checkLocalRead(ctx, "/storage-authorize", "managed-storage-auth-v1", c)
}
func (h *HostAuthority) CompletionResponseMAC(raw []byte) string {
	return h.responseMAC("managed-completion-response-v1", raw)
}

// SearchResponseMAC authenticates the exact serialized managed-search payload.
func (h *HostAuthority) SearchResponseMAC(raw []byte) string {
	return h.responseMAC("managed-search-response-v1", raw)
}

func (h *HostAuthority) responseMAC(domain string, raw []byte) string {
	derive := hmac.New(sha256.New, h.callbackKey)
	derive.Write([]byte(domain))
	m := hmac.New(sha256.New, derive.Sum(nil))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil))
}

func (h *HostAuthority) DiscoverCheck(ctx context.Context, c CompletionDiscover) error {
	return h.checkLocalRead(ctx, "/completed-authorize", "completed-index-discover-auth-v1", c)
}
