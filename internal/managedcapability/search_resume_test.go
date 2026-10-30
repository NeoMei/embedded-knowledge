package managedcapability

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSearchNotSubmittedRequiresBoundSignedAbsence(t *testing.T) {
	v, key, _, _, now := fixture(t)
	b := SearchBinding{IndexBinding: IndexBinding{NamespaceID: strings.Repeat("1", 64), StorageID: strings.Repeat("2", 64), StorageGeneration: strings.Repeat("3", 64), EmbeddingPolicyDigest: strings.Repeat("4", 64), OpaquePin: strings.Repeat("5", 64), RouteGeneration: strings.Repeat("6", 64), IndexRevision: 1}, CompletionDigest: strings.Repeat("7", 64), IndexWorkID: "index-work", TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "search-work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: EmbeddingModel, EmbeddingSpace: EmbeddingSpace, RerankModel: "qwen3-rerank"}
	input := []byte(`{"model":"qwen3-rerank","input":{"query":"query","documents":["document"]},"parameters":{"top_n":1,"return_documents":false}}`)
	sum := sha256.Sum256(input)
	digest := hex.EncodeToString(sum[:])
	mutations := map[string]func(map[string]any){
		"valid":          func(map[string]any) {},
		"actor":          func(c map[string]any) { c["actor_id"] = "other" },
		"payer":          func(c map[string]any) { c["account_id"] = "other" },
		"task":           func(c map[string]any) { c["task_id"] = "other" },
		"work":           func(c map[string]any) { c["work_id"] = "other" },
		"grant":          func(c map[string]any) { c["grant_id"] = "other" },
		"tenant":         func(c map[string]any) { c["tenant_id"] = 2 },
		"knowledge":      func(c map[string]any) { c["knowledge_id"] = "other" },
		"kb":             func(c map[string]any) { c["knowledge_base_id"] = "other" },
		"query":          func(c map[string]any) { c["query_digest"] = strings.Repeat("b", 64) },
		"namespace":      func(c map[string]any) { c["namespace_id"] = strings.Repeat("b", 64) },
		"storage":        func(c map[string]any) { c["storage_id"] = strings.Repeat("b", 64) },
		"generation":     func(c map[string]any) { c["storage_generation"] = strings.Repeat("b", 64) },
		"policy":         func(c map[string]any) { c["embedding_policy_digest"] = strings.Repeat("b", 64) },
		"opaque":         func(c map[string]any) { c["opaque_pin"] = strings.Repeat("b", 64) },
		"route":          func(c map[string]any) { c["route_generation"] = strings.Repeat("b", 64) },
		"revision":       func(c map[string]any) { c["index_revision"] = 2 },
		"completion":     func(c map[string]any) { c["completion_digest"] = strings.Repeat("b", 64) },
		"index_work":     func(c map[string]any) { c["index_work_id"] = "other" },
		"nonce":          func(c map[string]any) { c["nonce"] = strings.Repeat("b", 64) },
		"call":           func(c map[string]any) { c["call_id"] = "other" },
		"model":          func(c map[string]any) { c["model"] = EmbeddingModel },
		"operation":      func(c map[string]any) { c["operation"] = "embedding" },
		"wire":           func(c map[string]any) { c["wire_operation"] = "embeddings.create" },
		"input":          func(c map[string]any) { c["input_sha256"] = strings.Repeat("b", 64) },
		"status":         func(c map[string]any) { c["status"] = "UNKNOWN" },
		"issuer":         func(c map[string]any) { c["issuer"] = "other" },
		"audience":       func(c map[string]any) { c["audience"] = "other" },
		"expired":        func(c map[string]any) { c["expires_at"] = now.Unix() },
		"future":         func(c map[string]any) { c["issued_at"] = now.Unix() + 1 },
		"long":           func(c map[string]any) { c["expires_at"] = now.Unix() + 31 },
		"unknown_field":  func(c map[string]any) { c["extra"] = true },
		"bad_signature":  func(map[string]any) {},
		"wrong_domain":   func(map[string]any) {},
		"mixed_response": func(map[string]any) {},
		"http404":        func(map[string]any) {},
		"http403":        func(map[string]any) {},
	}
	mutations["timeout"] = func(map[string]any) {}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if name == "timeout" {
					time.Sleep(20 * time.Millisecond)
					return
				}
				var req map[string]string
				require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
				if strings.HasSuffix(r.URL.Path, "/dispatch") {
					w.WriteHeader(503)
					return
				}
				if name == "http404" {
					w.WriteHeader(404)
					return
				}
				if name == "http403" {
					w.WriteHeader(403)
					return
				}
				if name == "valid" {
					require.Equal(t, digest, req["input_sha256"])
				}
				raw, _ := json.Marshal(b)
				var claims map[string]any
				require.NoError(t, json.Unmarshal(raw, &claims))
				for k, v := range map[string]any{"issuer": "fixture-issuer", "audience": "weknora-document", "nonce": req["nonce"], "call_id": "call-rerank", "model": "qwen3-rerank", "operation": "rerank", "wire_operation": "rerank.create", "input_sha256": digest, "status": "NOT_SUBMITTED", "issued_at": now.Unix(), "expires_at": now.Unix() + 30} {
					claims[k] = v
				}
				change(claims)
				raw, _ = json.Marshal(claims)
				kind := "weknora-search-not-submitted-v1"
				if name == "wrong_domain" {
					kind = "weknora-search-result-v1"
				}
				prefix := kind + ".key-1." + base64.RawURLEncoding.EncodeToString(raw)
				signature := ed25519.Sign(key, []byte(prefix))
				if name == "bad_signature" {
					signature[0] ^= 1
				}
				token := prefix + "." + base64.RawURLEncoding.EncodeToString(signature)
				response := map[string]string{"not_submitted_assertion": token}
				if name == "mixed_response" {
					response["assertion"] = token
					response["content"] = "e30="
				}
				require.NoError(t, json.NewEncoder(w).Encode(response))
			}))
			defer server.Close()
			host, err := NewHostAuthority(server.URL+"/internal/knowledge-work/authorize", v, server.Client(), []byte("0123456789abcdef0123456789abcdef"))
			require.NoError(t, err)
			ctx := context.Background()
			if name == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Millisecond)
				defer cancel()
			}
			result, err := host.SearchDispatch(ctx, b, "call-rerank", "rerank", input)
			require.Nil(t, result)
			require.Error(t, err)
			if name == "timeout" {
				require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
			}
			if name == "valid" {
				require.Equal(t, "managed search not submitted", err.Error())
			} else {
				require.ErrorIs(t, err, ErrInvalid)
			}
		})
	}
}

type searchResumeRoundTripper func(*http.Request) (*http.Response, error)

func (f searchResumeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSearchDispatchOnlyHasLongDeadline(t *testing.T) {
	v, key, _, _, now := fixture(t)
	b := SearchBinding{TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: EmbeddingModel, EmbeddingSpace: EmbeddingSpace, RerankModel: "qwen3-rerank"}
	seen := map[string]time.Duration{}
	client := &http.Client{Transport: searchResumeRoundTripper(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		require.True(t, ok)
		seen[r.URL.Path] = time.Until(deadline)
		payload := `{"status":"submitted"}`
		if strings.HasSuffix(r.URL.Path, "/result") {
			var req map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			body := []byte(`{"ok":true}`)
			sum := sha256.Sum256(body)
			c := SearchResultClaims{Issuer: "fixture-issuer", Audience: "weknora-document", SearchBinding: b, Nonce: req["nonce"], IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 30, CallID: "call", Model: EmbeddingModel, Operation: "embedding", WireOperation: "embeddings.create", Status: "SETTLED", ContentSHA256: hex.EncodeToString(sum[:])}
			raw, _ := json.Marshal(c)
			prefix := "weknora-search-result-v1.key-1." + base64.RawURLEncoding.EncodeToString(raw)
			out, _ := json.Marshal(map[string]string{"assertion": prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix))), "content": base64.StdEncoding.EncodeToString(body)})
			payload = string(out)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
	})}
	host, err := NewHostAuthority("http://127.0.0.1:12345/internal/knowledge-work/authorize", v, client, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	_, err = host.SearchDispatch(context.Background(), b, "call", "embedding", []byte("input"))
	require.NoError(t, err)
	require.Greater(t, seen["/internal/knowledge-search/dispatch"], 110*time.Second)
	require.LessOrEqual(t, seen["/internal/knowledge-search/result"], 5*time.Second)
	require.Greater(t, seen["/internal/knowledge-search/result"], 4*time.Second)
}
