package managedcapability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type SearchBinding struct {
	TenantID        uint64 `json:"tenant_id"`
	ActorID         string `json:"actor_id"`
	AccountID       string `json:"account_id"`
	TaskID          string `json:"task_id"`
	WorkID          string `json:"work_id"`
	GrantID         string `json:"grant_id"`
	KnowledgeBaseID string `json:"knowledge_base_id"`
	KnowledgeID     string `json:"knowledge_id"`
	QueryDigest     string `json:"query_digest"`
	EmbeddingModel  string `json:"embedding_model"`
	EmbeddingSpace  string `json:"embedding_space"`
	RerankModel     string `json:"rerank_model"`
}
type SearchClaims struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	SearchBinding
	IssuedAt  int64 `json:"issued_at"`
	ExpiresAt int64 `json:"expires_at"`
}
type SearchSnapshotClaims struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	SearchBinding
	Nonce         string `json:"nonce"`
	IssuedAt      int64  `json:"issued_at"`
	ExpiresAt     int64  `json:"expires_at"`
	ContentSHA256 string `json:"content_sha256"`
}
type SearchActiveClaims struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	SearchBinding
	Nonce     string `json:"nonce"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}
type SearchResultClaims struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	SearchBinding
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

func validSearch(b SearchBinding) bool {
	return b.TenantID != 0 && identifier.MatchString(b.ActorID) && identifier.MatchString(b.AccountID) && identifier.MatchString(b.TaskID) && identifier.MatchString(b.WorkID) && identifier.MatchString(b.GrantID) && identifier.MatchString(b.KnowledgeBaseID) && identifier.MatchString(b.KnowledgeID) && digest.MatchString(b.QueryDigest) && b.EmbeddingModel == EmbeddingModel && b.EmbeddingSpace == EmbeddingSpace && b.RerankModel == "qwen3-rerank"
}
func (v *Verifier) validWindow(issued, expires, max int64) bool {
	if v == nil {
		return false
	}
	now := v.now().Unix()
	return issued > 0 && issued <= now && expires > now && expires > issued && expires-issued <= max
}
func (v *Verifier) VerifySearch(token string, b SearchBinding) (SearchClaims, error) {
	var c SearchClaims
	if !validSearch(b) || v.verifyEnvelope(token, "weknora-search-v1", &c) != nil || c.Issuer != v.issuer || c.Audience != v.audience || c.SearchBinding != b || !v.validWindow(c.IssuedAt, c.ExpiresAt, int64(v.lifetime/time.Second)) {
		return SearchClaims{}, ErrInvalid
	}
	return c, nil
}
func (v *Verifier) DecodeSearch(token string) (SearchClaims, error) {
	var c SearchClaims
	if v.verifyEnvelope(token, "weknora-search-v1", &c) != nil {
		return SearchClaims{}, ErrInvalid
	}
	return v.VerifySearch(token, c.SearchBinding)
}
func (v *Verifier) VerifySearchActive(token string, b SearchBinding, nonce string) (SearchActiveClaims, error) {
	var c SearchActiveClaims
	if !validSearch(b) || !digest.MatchString(nonce) || v.verifyEnvelope(token, "weknora-search-auth-v1", &c) != nil || c.Issuer != v.issuer || c.Audience != v.audience || c.SearchBinding != b || c.Nonce != nonce || !v.validWindow(c.IssuedAt, c.ExpiresAt, 30) {
		return SearchActiveClaims{}, ErrInvalid
	}
	return c, nil
}
func (v *Verifier) VerifySearchSnapshot(token string, b SearchBinding, nonce string, body []byte) (SearchSnapshotClaims, error) {
	var c SearchSnapshotClaims
	if !validSearch(b) || !digest.MatchString(nonce) || len(body) == 0 || len(body) > 300 || v.verifyEnvelope(token, "weknora-search-snapshot-v1", &c) != nil || c.Issuer != v.issuer || c.Audience != v.audience || c.SearchBinding != b || c.Nonce != nonce || !v.validWindow(c.IssuedAt, c.ExpiresAt, 30) {
		return SearchSnapshotClaims{}, ErrInvalid
	}
	sum := sha256.Sum256(body)
	if !hmac.Equal([]byte(c.ContentSHA256), []byte(hex.EncodeToString(sum[:]))) {
		return SearchSnapshotClaims{}, ErrInvalid
	}
	return c, nil
}
func (v *Verifier) VerifySearchResult(token string, b SearchBinding, nonce, callID, model, operation, wire string, body []byte) (SearchResultClaims, error) {
	var c SearchResultClaims
	if !validSearch(b) || !digest.MatchString(nonce) || !identifier.MatchString(callID) || len(body) == 0 || len(body) > 16<<20 || v.verifyEnvelope(token, "weknora-search-result-v1", &c) != nil || c.Issuer != v.issuer || c.Audience != v.audience || c.SearchBinding != b || c.Nonce != nonce || c.CallID != callID || c.Model != model || c.Operation != operation || c.WireOperation != wire || c.Status != "SETTLED" || !v.validWindow(c.IssuedAt, c.ExpiresAt, 30) {
		return SearchResultClaims{}, ErrInvalid
	}
	sum := sha256.Sum256(body)
	if !hmac.Equal([]byte(c.ContentSHA256), []byte(hex.EncodeToString(sum[:]))) {
		return SearchResultClaims{}, ErrInvalid
	}
	return c, nil
}
