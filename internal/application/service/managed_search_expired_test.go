package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
)

func TestExpiredManagedSearchReadsSettledOriginalCallsWithoutDispatch(t *testing.T) {
	for _, mode := range []string{"settled", "concurrent", "not_submitted", "http404", "actor", "payer", "task", "call", "policy", "generation", "expired_proof", "expired_search", "signature", "input", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompletionFixture(t)
			f.ingest()
			require.NoError(t, f.finalize())
			use := f.use()
			f.search = managedcapability.SearchBinding{IndexBinding: f.binding.IndexBinding, CompletionDigest: use.CompletionDigest, IndexWorkID: "work", TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "search-grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: f.binding.EmbeddingModel, EmbeddingSpace: f.binding.EmbeddingSpace, RerankModel: "qwen3-rerank"}
			journal, err := managedjournal.Open(f.db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Second)
			require.NoError(t, err)
			f.worker.journal = journal
			svc := &knowledgeBaseService{managedWorker: f.worker, kgRepo: completionKnowledgeRepo{db: f.db}}
			ctx := context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1))
			now := f.now.Load()
			token := f.sign("weknora-search-v1", managedcapability.SearchClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, IssuedAt: now, ExpiresAt: now + 30})
			_, err = svc.ManagedHybridSearch(ctx, "kb", token)
			require.NoError(t, err)
			require.EqualValues(t, 3, f.dispatches.Load())
			input, _ := json.Marshal(struct {
				Model      string   `json:"model"`
				Input      []string `json:"input"`
				Dimensions int      `json:"dimensions"`
			}{f.search.EmbeddingModel, []string{"query"}, 1024})
			scope := managedjournal.Scope{TenantID: "1", ActorID: "actor", AccountID: "payer", TaskID: "search-task", LogicalID: "search-work", Operation: "embedding", Model: f.search.EmbeddingModel, PlanDigest: managedSHA(input), Batch: 0}
			old, err := journal.Inspect(ctx, scope, input)
			require.NoError(t, err)
			time.Sleep(1100 * time.Millisecond)
			_, err = journal.Execute(ctx, scope, input, func(context.Context, string) ([]byte, error) {
				t.Error("expired execute must never dispatch")
				return nil, nil
			})
			require.ErrorIs(t, err, managedjournal.ErrExpired)
			expired, err := journal.Inspect(ctx, scope, input)
			require.NoError(t, err)
			require.Equal(t, "EXPIRED", expired.Status)
			require.Equal(t, old.CallID, expired.CallID)
			var erased struct {
				ResultHash string
				Result     []byte
			}
			require.NoError(t, f.db.Table("managed_model_requests").Where("call_id = ?", old.CallID).First(&erased).Error)
			require.Empty(t, erased.ResultHash)
			require.Empty(t, erased.Result)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/dispatch") {
					t.Error("EXPIRED/COMPLETED search must never dispatch")
					w.WriteHeader(503)
					return
				}
				if mode == "input" && strings.HasSuffix(r.URL.Path, "/snapshot") {
					var req map[string]string
					require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
					query := []byte("changed query")
					claims := managedcapability.SearchSnapshotClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, Nonce: req["nonce"], IssuedAt: now, ExpiresAt: now + 30, ContentSHA256: managedSHA(query)}
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": f.sign("weknora-search-snapshot-v1", claims), "content": base64.StdEncoding.EncodeToString(query)}))
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/result") || !strings.HasPrefix(r.URL.Path, "/internal/knowledge-search/") || mode == "settled" || mode == "concurrent" {
					f.serve(w, r)
					return
				}
				var req map[string]string
				require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
				if mode == "http404" {
					w.WriteHeader(404)
					return
				}
				if mode == "not_submitted" {
					c := managedcapability.SearchNotSubmittedClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, Nonce: req["nonce"], IssuedAt: now, ExpiresAt: now + 30, CallID: req["call_id"], Model: f.search.EmbeddingModel, Operation: "embedding", WireOperation: "embeddings.create", Status: "NOT_SUBMITTED", InputSHA256: managedSHA(input)}
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"not_submitted_assertion": f.sign("weknora-search-not-submitted-v1", c)}))
					return
				}
				c := managedcapability.SearchResultClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, Nonce: req["nonce"], IssuedAt: now, ExpiresAt: now + 30, CallID: req["call_id"], Model: f.search.EmbeddingModel, Operation: "embedding", WireOperation: "embeddings.create", Status: "SETTLED", ContentSHA256: managedSHA(f.raw)}
				switch mode {
				case "actor":
					c.ActorID = "other"
				case "payer":
					c.AccountID = "other"
				case "task":
					c.TaskID = "other"
				case "call":
					c.CallID = "other"
				case "policy":
					c.EmbeddingPolicyDigest = strings.Repeat("b", 64)
				case "generation":
					c.StorageGeneration = strings.Repeat("b", 64)
				case "expired_proof":
					c.ExpiresAt = now
				case "unknown":
					c.Status = "UNKNOWN"
				case "expired_search":
					f.now.Add(31)
					c.IssuedAt = now + 31
					c.ExpiresAt = now + 61
				}
				assertion := f.sign("weknora-search-result-v1", c)
				if mode == "signature" {
					assertion = strings.Replace(assertion, "host-v1", "invalid-key", 1)
				}
				require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": assertion, "content": base64.StdEncoding.EncodeToString(f.raw)}))
			}))
			defer server.Close()
			f.worker.host, err = managedcapability.NewHostAuthority(server.URL+"/internal/knowledge-work/authorize", f.verifier, server.Client(), []byte("0123456789abcdef0123456789abcdef"))
			require.NoError(t, err)
			var before map[string]any
			require.NoError(t, f.db.Table("managed_model_requests").Where("call_id = ?", old.CallID).Take(&before).Error)
			if mode == "concurrent" {
				start := make(chan struct{})
				results := make(chan error, 2)
				for range 2 {
					go func() { <-start; _, e := svc.ManagedHybridSearch(ctx, "kb", token); results <- e }()
				}
				close(start)
				a, b := <-results, <-results
				require.True(t, a == nil || b == nil)
			} else {
				result, e := svc.ManagedHybridSearch(ctx, "kb", token)
				if mode == "settled" {
					require.NoError(t, e)
					require.Len(t, result.Results, 1)
					require.Equal(t, string(f.document), result.Results[0].Content)
				} else {
					require.Error(t, e)
					require.Nil(t, result)
				}
			}
			after, err := journal.Inspect(ctx, scope, input)
			require.NoError(t, err)
			require.Equal(t, old.CallID, after.CallID)
			require.EqualValues(t, 3, f.dispatches.Load(), "only original ingest/query/rerank ever dispatched")
			if mode == "settled" || mode == "concurrent" {
				require.Equal(t, "COMPLETED", after.Status)
				var restored struct {
					ResultHash string
					Result     []byte
					ExpiresAt  int64
				}
				require.NoError(t, f.db.Table("managed_model_requests").Where("call_id = ?", old.CallID).First(&restored).Error)
				require.NotEmpty(t, restored.ResultHash)
				require.NotEmpty(t, restored.Result)
				require.False(t, bytes.Contains(restored.Result, f.raw))
				require.LessOrEqual(t, restored.ExpiresAt, (now+30)*1000)
			} else {
				require.Equal(t, "EXPIRED", after.Status)
				var unchanged map[string]any
				require.NoError(t, f.db.Table("managed_model_requests").Where("call_id = ?", old.CallID).Take(&unchanged).Error)
				require.Equal(t, before, unchanged, "invalid proofs never restore or mutate the original expired row")
			}
		})
	}
}
