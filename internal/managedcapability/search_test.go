package managedcapability

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSearchCapabilityAndSnapshotBindActorPayerQuery(t *testing.T) {
	v, key, _, _, now := fixture(t)
	b := SearchBinding{EmbeddingSpace: EmbeddingSpace, TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: EmbeddingModel, RerankModel: "qwen3-rerank"}
	sign := func(kind string, v any) string {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		prefix := kind + ".key-1." + base64.RawURLEncoding.EncodeToString(raw)
		return prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
	}
	claims := SearchClaims{Issuer: "fixture-issuer", Audience: "weknora-document", SearchBinding: b, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	token := sign("weknora-search-v1", claims)
	got, err := v.VerifySearch(token, b)
	require.NoError(t, err)
	require.Equal(t, claims, got)
	changed := b
	changed.AccountID = "other"
	_, err = v.VerifySearch(token, changed)
	require.Error(t, err)
	content := []byte("query")
	sum := sha256.Sum256(content)
	nonce := strings.Repeat("c", 64)
	snapshot := SearchSnapshotClaims{Issuer: claims.Issuer, Audience: claims.Audience, SearchBinding: b, Nonce: nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), ContentSHA256: hex.EncodeToString(sum[:])}
	_, err = v.VerifySearchSnapshot(sign("weknora-search-snapshot-v1", snapshot), b, nonce, content)
	require.NoError(t, err)
	_, err = v.VerifySearchSnapshot(sign("weknora-search-snapshot-v1", snapshot), b, nonce, []byte("altered"))
	require.Error(t, err)
}

func TestSearchHostCallsRequireDistinctSignedSettledOperations(t *testing.T) {
	v, key, _, _, now := fixture(t)
	binding := SearchBinding{EmbeddingSpace: EmbeddingSpace, TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: EmbeddingModel, RerankModel: "qwen3-rerank"}
	sign := func(kind string, x any) string {
		raw, err := json.Marshal(x)
		require.NoError(t, err)
		prefix := kind + ".key-1." + base64.RawURLEncoding.EncodeToString(raw)
		return prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
	}
	counts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			WorkID    string `json:"work_id"`
			Nonce     string `json:"nonce"`
			CallID    string `json:"call_id"`
			Operation string `json:"operation"`
			Content   string `json:"content"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		counts[r.URL.Path]++
		require.Equal(t, binding.WorkID, req.WorkID)
		switch r.URL.Path {
		case "/internal/knowledge-search/authorize":
			c := SearchActiveClaims{Issuer: "fixture-issuer", Audience: "weknora-document", SearchBinding: binding, Nonce: req.Nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix()}
			_ = json.NewEncoder(w).Encode(map[string]string{"assertion": sign("weknora-search-auth-v1", c)})
		case "/internal/knowledge-search/snapshot":
			body := []byte("hello")
			sum := sha256.Sum256(body)
			c := SearchSnapshotClaims{Issuer: "fixture-issuer", Audience: "weknora-document", SearchBinding: binding, Nonce: req.Nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), ContentSHA256: hex.EncodeToString(sum[:])}
			_ = json.NewEncoder(w).Encode(map[string]string{"assertion": sign("weknora-search-snapshot-v1", c), "content": base64.StdEncoding.EncodeToString(body)})
		case "/internal/knowledge-search/dispatch":
			_, _ = w.Write([]byte(`{"status":"submitted"}`))
		case "/internal/knowledge-search/result":
			body := []byte(`{"ok":true}`)
			sum := sha256.Sum256(body)
			model, wire := binding.EmbeddingModel, "embeddings.create"
			if req.Operation == "rerank" {
				model, wire = binding.RerankModel, "rerank.create"
			}
			c := SearchResultClaims{Issuer: "fixture-issuer", Audience: "weknora-document", SearchBinding: binding, Nonce: req.Nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), CallID: req.CallID, Model: model, Operation: req.Operation, WireOperation: wire, Status: "SETTLED", ContentSHA256: hex.EncodeToString(sum[:])}
			_ = json.NewEncoder(w).Encode(map[string]string{"assertion": sign("weknora-search-result-v1", c), "content": base64.StdEncoding.EncodeToString(body)})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	host, err := NewHostAuthority(server.URL+"/internal/knowledge-work/authorize", v, server.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	require.NoError(t, host.SearchCheck(context.Background(), binding))
	query, err := host.SearchSnapshot(context.Background(), binding)
	require.NoError(t, err)
	require.Equal(t, "hello", string(query))
	for _, operation := range []string{"embedding", "rerank"} {
		result, err := host.SearchDispatch(context.Background(), binding, "call-"+operation, operation, []byte("input"))
		require.NoError(t, err)
		require.JSONEq(t, `{"ok":true}`, string(result))
	}
	require.Equal(t, 2, counts["/internal/knowledge-search/dispatch"])
	require.Equal(t, 2, counts["/internal/knowledge-search/result"])
}

func TestRequestProofBindsBodyPathAndIdentity(t *testing.T) {
	verifier, key, _, _, now := fixture(t)
	body := []byte(`{"capability":"secret"}`)
	sum := sha256.Sum256(body)
	nonce := strings.Repeat("c", 64)
	claims := RequestClaims{Issuer: "fixture-issuer", Audience: "weknora-document", Method: "POST", Path: "/api/v1/managed", BodySHA256: hex.EncodeToString(sum[:]), Nonce: nonce, WorkID: "work", ActorID: "actor", AccountID: "payer", IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix()}
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	prefix := "weknora-request-v1.key-1." + base64.RawURLEncoding.EncodeToString(raw)
	token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
	_, err = verifier.VerifyRequest(token, "POST", claims.Path, body, "work", "actor", "payer")
	require.NoError(t, err)
	_, err = verifier.VerifyRequest(token, "POST", claims.Path, []byte("changed"), "work", "actor", "payer")
	require.Error(t, err)
	_, err = verifier.VerifyRequest(token, "POST", claims.Path, body, "work", "other", "payer")
	require.Error(t, err)
}
