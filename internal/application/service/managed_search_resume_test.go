package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedSearchResumesOnlySignedUnsubmittedOriginalCall(t *testing.T) {
	for _, mode := range []string{"signed_absence", "concurrent", "http404", "http403", "bad_signature", "claimed_unknown", "expired_absence"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompletionFixture(t)
			f.ingest()
			require.NoError(t, f.finalize())
			use := f.use()
			f.search = managedcapability.SearchBinding{IndexBinding: f.binding.IndexBinding, CompletionDigest: use.CompletionDigest, IndexWorkID: "work", TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "search-grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: f.binding.EmbeddingModel, EmbeddingSpace: f.binding.EmbeddingSpace, RerankModel: "qwen3-rerank"}
			now := f.now.Load()
			token := f.sign("weknora-search-v1", managedcapability.SearchClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, IssuedAt: now, ExpiresAt: now + 30})
			var resume atomic.Bool
			var mu sync.Mutex
			var originalInput []byte
			var originalCall string
			var claimed bool
			var rerankProviderCalls int
			var dispatchCalls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/internal/knowledge-search/") {
					f.serve(w, r)
					return
				}
				raw, e := io.ReadAll(r.Body)
				require.NoError(t, e)
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var req map[string]string
				require.NoError(t, json.Unmarshal(raw, &req))
				if strings.HasPrefix(r.URL.Path, "/internal/knowledge-search/") && req["operation"] == "rerank" {
					mu.Lock()
					if strings.HasSuffix(r.URL.Path, "/dispatch") {
						input, e := base64.StdEncoding.DecodeString(req["content"])
						require.NoError(t, e)
						dispatchCalls = append(dispatchCalls, req["call_id"])
						if originalCall == "" {
							originalCall = req["call_id"]
							originalInput = append([]byte(nil), input...)
						}
						assert.Equal(t, originalCall, req["call_id"])
						assert.Equal(t, originalInput, input)
						if !resume.Load() {
							mu.Unlock()
							w.WriteHeader(503)
							return
						}
						if claimed {
							mu.Unlock()
							w.WriteHeader(200)
							return
						}
						claimed = true
						rerankProviderCalls++
						mu.Unlock()
						f.serve(w, r)
						return
					}
					if strings.HasSuffix(r.URL.Path, "/result") && !claimed {
						if !resume.Load() || mode == "claimed_unknown" || mode == "http403" {
							mu.Unlock()
							w.WriteHeader(403)
							return
						}
						if mode == "http404" {
							mu.Unlock()
							w.WriteHeader(404)
							return
						}
						assert.Equal(t, originalCall, req["call_id"])
						assert.Equal(t, managedSHA(originalInput), req["input_sha256"])
						c := managedcapability.SearchNotSubmittedClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, Nonce: req["nonce"], IssuedAt: now, ExpiresAt: now + 30, CallID: originalCall, Model: f.search.RerankModel, Operation: "rerank", WireOperation: "rerank.create", Status: "NOT_SUBMITTED", InputSHA256: managedSHA(originalInput)}
						if mode == "expired_absence" {
							c.ExpiresAt = now
						}
						assertion := f.sign("weknora-search-not-submitted-v1", c)
						if mode == "bad_signature" {
							assertion = strings.Replace(assertion, "host-v1", "other-key", 1)
						}
						mu.Unlock()
						require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"not_submitted_assertion": assertion}))
						return
					}
					mu.Unlock()
				}
				f.serve(w, r)
			}))
			defer server.Close()
			host, e := managedcapability.NewHostAuthority(server.URL+"/internal/knowledge-work/authorize", f.verifier, server.Client(), []byte("0123456789abcdef0123456789abcdef"))
			require.NoError(t, e)
			f.host = host
			f.worker.host = host
			svc := &knowledgeBaseService{managedWorker: f.worker, kgRepo: completionKnowledgeRepo{db: f.db}}
			ctx := context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1))
			_, e = svc.ManagedHybridSearch(ctx, "kb", token)
			require.Error(t, e)
			require.EqualValues(t, 2, f.dispatches.Load(), "only ingest and query embedding reached provider before absent rerank")
			scope := managedjournal.Scope{TenantID: "1", ActorID: "actor", AccountID: "payer", TaskID: "search-task", LogicalID: "search-work", Operation: "rerank", Model: "qwen3-rerank", PlanDigest: managedSHA(originalInput), Batch: 0}
			old, e := f.worker.journal.Inspect(ctx, scope, originalInput)
			require.NoError(t, e)
			require.Equal(t, "DISPATCHED", old.Status)
			key, _ := json.Marshal([]any{f.search.WorkID, "rerank", 0})
			mac := hmac.New(sha256.New, []byte("abcdef0123456789abcdef0123456789"))
			_, _ = mac.Write([]byte("managed-journal:call-id:v1\x00"))
			_, _ = mac.Write(key)
			require.Equal(t, "wk_"+hex.EncodeToString(mac.Sum(nil))[:60], old.CallID, "real worker journal matches host stable call derivation")
			resume.Store(true)
			success := mode == "signed_absence" || mode == "concurrent"
			if mode == "concurrent" {
				start := make(chan struct{})
				outcomes := make(chan error, 2)
				for range 2 {
					go func() { <-start; _, e := svc.ManagedHybridSearch(ctx, "kb", token); outcomes <- e }()
				}
				close(start)
				one, two := <-outcomes, <-outcomes
				require.True(t, one == nil || two == nil, "at least one exact-scope recovery succeeds")
			} else {
				result, e := svc.ManagedHybridSearch(ctx, "kb", token)
				if success {
					require.NoError(t, e)
					require.Len(t, result.Results, 1)
				} else {
					require.Error(t, e)
					require.Nil(t, result)
				}
			}
			current, e := f.worker.journal.Inspect(ctx, scope, originalInput)
			require.NoError(t, e)
			require.Equal(t, old.CallID, current.CallID)
			mu.Lock()
			providerCalls := rerankProviderCalls
			calls := append([]string(nil), dispatchCalls...)
			mu.Unlock()
			if success {
				require.Equal(t, 1, providerCalls)
				require.Equal(t, "COMPLETED", current.Status)
				_, e = svc.ManagedHybridSearch(ctx, "kb", token)
				require.NoError(t, e)
				require.EqualValues(t, 3, f.dispatches.Load(), "completed embedding and recovered rerank are never submitted again")
			} else {
				require.Zero(t, providerCalls)
				require.Equal(t, old, current, "ambiguous outcomes preserve exact DISPATCHED record")
				require.Len(t, calls, 1, "generic errors and existing UNKNOWN never dispatch again")
			}
			for _, call := range calls {
				require.Equal(t, old.CallID, call)
			}
		})
	}
}

func TestManagedSearchExpiredDeliveryFreshProofReusesCompletedCalls(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	use := f.use()
	f.search = managedcapability.SearchBinding{IndexBinding: f.binding.IndexBinding, CompletionDigest: use.CompletionDigest, IndexWorkID: "work", TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "search-grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: f.binding.EmbeddingModel, EmbeddingSpace: f.binding.EmbeddingSpace, RerankModel: "qwen3-rerank"}
	svc := &knowledgeBaseService{managedWorker: f.worker, kgRepo: completionKnowledgeRepo{db: f.db}}
	ctx := context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1))
	f.duringRerank = func() { f.now.Add(31) }
	request := func(nonce string) (*ManagedSearchResponse, error) {
		now := f.now.Load()
		token := f.sign("weknora-search-v1", managedcapability.SearchClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, IssuedAt: now, ExpiresAt: now + 30})
		body, _ := json.Marshal(map[string]string{"capability": token})
		path := "/api/v1/knowledge-bases/kb/managed-hybrid-search"
		proof := f.sign("weknora-request-v1", managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: path, BodySHA256: managedSHA(body), Nonce: nonce, WorkID: f.search.WorkID, ActorID: f.search.ActorID, AccountID: f.search.AccountID, IssuedAt: now, ExpiresAt: now + 30})
		return svc.ManagedHybridSearchWithEvidence(ctx, 1, "kb", "POST", path, body, token, proof)
	}
	result, err := request(strings.Repeat("c", 64))
	require.Error(t, err)
	require.Nil(t, result)
	require.EqualValues(t, 3, f.dispatches.Load())
	f.duringRerank = nil
	result, err = request(strings.Repeat("d", 64))
	require.NoError(t, err)
	require.NotNil(t, result)
	require.EqualValues(t, 3, f.dispatches.Load(), "fresh delivery proof recovers same completed operations without provider replay")
}
