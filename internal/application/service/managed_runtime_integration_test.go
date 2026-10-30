package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/application/service/retriever"
	"github.com/Tencent/WeKnora/internal/infrastructure/chunker"
	"github.com/Tencent/WeKnora/internal/infrastructure/docparser"
	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/models/api/openaiembeddings"
	"github.com/Tencent/WeKnora/internal/models/embedding"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type pilotEmbedder struct{ client *openaiembeddings.Client }

func (e pilotEmbedder) Embed(ctx context.Context, s string) ([]float32, error) {
	v, err := e.BatchEmbed(ctx, []string{s})
	if err != nil {
		return nil, err
	}
	return v[0], nil
}
func (e pilotEmbedder) BatchEmbed(ctx context.Context, s []string) ([][]float32, error) {
	return e.client.Embed(ctx, s, api.EmbedDocument)
}
func (e pilotEmbedder) BatchEmbedWithPool(ctx context.Context, _ embedding.Embedder, s []string) ([][]float32, error) {
	return e.BatchEmbed(api.WithManagedBatchStart(ctx, 0), s)
}
func (pilotEmbedder) GetModelName() string { return managedcapability.EmbeddingModel }
func (pilotEmbedder) GetModelID() string   { return "fixture" }
func (pilotEmbedder) GetDimensions() int   { return managedcapability.EmbeddingDimensions }

type pilotIndexRepo struct {
	interfaces.RetrieveEngineRepository
	saves atomic.Int32
}

func (p *pilotIndexRepo) BatchSave(context.Context, []*types.IndexInfo, map[string]any) error {
	p.saves.Add(1)
	return nil
}

func TestPilotRegistrationParserAndIndexRequireSignedSettledResult(t *testing.T) {
	for _, settled := range []bool{true, false} {
		t.Run(fmt.Sprintf("settled_%t", settled), func(t *testing.T) {
			document := []byte(strings.Repeat("a", 300))
			file := filepath.Join(t.TempDir(), "fixture.txt")
			require.NoError(t, os.WriteFile(file, document, 0600))
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			now := time.Now()
			verifier, err := managedcapability.NewVerifier("superwagie-knowledge-v1", "weknora", map[string]ed25519.PublicKey{"host-v1": pub}, time.Hour, time.Now)
			require.NoError(t, err)
			binding := managedcapability.Binding{EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace, TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb-1", KnowledgeID: "22ae397e-8e09-4567-8453-340f88a1bda6", Purpose: "document-ingest", InputDigest: strings.Repeat("a", 64)}
			sign := func(prefix string, v any) string {
				raw, err := json.Marshal(v)
				require.NoError(t, err)
				prefix = prefix + ".host-v1." + base64.RawURLEncoding.EncodeToString(raw)
				return prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(prefix)))
			}
			capability := sign("weknora-cap-v1", managedcapability.Claims{Issuer: "superwagie-knowledge-v1", Audience: "weknora", Binding: binding, IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(time.Minute).Unix()})
			allowResult := settled
			var dispatches atomic.Int32
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					WorkID  string `json:"work_id"`
					Nonce   string `json:"nonce"`
					CallID  string `json:"call_id"`
					Content string `json:"content"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				require.Equal(t, binding.WorkID, request.WorkID)
				issued := time.Now().Unix()
				active := managedcapability.ActiveClaims{Issuer: "superwagie-knowledge-v1", Audience: "weknora", Binding: binding, Nonce: request.Nonce, IssuedAt: issued, ExpiresAt: issued + 30}
				switch r.URL.Path {
				case "/internal/knowledge-work/authorize":
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": sign("weknora-auth-v1", active)}))
				case "/internal/knowledge-work/snapshot":
					sum := sha256.Sum256(document)
					snapshot := managedcapability.SnapshotClaims{Issuer: active.Issuer, Audience: active.Audience, Binding: binding, Nonce: active.Nonce, IssuedAt: issued, ExpiresAt: issued + 30, ContentSHA256: hex.EncodeToString(sum[:])}
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": sign("weknora-snapshot-v1", snapshot), "content": base64.StdEncoding.EncodeToString(document)}))
				case "/internal/knowledge-work/dispatch":
					dispatches.Add(1)
					body, err := base64.StdEncoding.DecodeString(request.Content)
					require.NoError(t, err)
					var model struct {
						Model string   `json:"model"`
						Input []string `json:"input"`
					}
					require.NoError(t, json.Unmarshal(body, &model))
					require.Equal(t, managedcapability.EmbeddingModel, model.Model)
					require.Equal(t, []string{"fixture.txt\n" + string(document)}, model.Input)
					_, _ = w.Write([]byte(`{"status":"submitted"}`))
				case "/internal/knowledge-work/result":
					if !allowResult {
						w.WriteHeader(404)
						return
					}
					result, err := json.Marshal(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": make([]float32, managedcapability.EmbeddingDimensions)}}})
					require.NoError(t, err)
					sum := sha256.Sum256(result)
					claims := managedcapability.ResultClaims{AttemptID: "fixture-attempt", ProducerCredentialID: "fixture-producer", Issuer: active.Issuer, Audience: active.Audience, Binding: binding, Nonce: request.Nonce, IssuedAt: issued, ExpiresAt: issued + 30, CallID: request.CallID, Model: managedcapability.EmbeddingModel, Operation: "embedding", WireOperation: "embeddings.create", Status: "SETTLED", ContentSHA256: hex.EncodeToString(sum[:])}
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": sign("weknora-result-v1", claims), "content": base64.StdEncoding.EncodeToString(result)}))
				default:
					w.WriteHeader(404)
				}
			}))
			defer host.Close()
			hostAuthority, err := managedcapability.NewHostAuthority(host.URL+"/internal/knowledge-work/authorize", verifier, host.Client(), []byte("0123456789abcdef0123456789abcdef"))
			require.NoError(t, err)
			db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "test.db")), &gorm.Config{})
			require.NoError(t, err)
			journal, err := managedjournal.Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
			require.NoError(t, err)
			worker, err := newPilotManagedWorker(db, verifier, hostAuthority, journal, []byte("9876543210abcdef9876543210abcdef"))
			require.NoError(t, err)
			binding.IndexBinding = managedcapability.IndexBinding{NamespaceID: strings.Repeat("1", 64), StorageID: worker.storage.StorageID, StorageGeneration: worker.storage.StorageGeneration, EmbeddingPolicyDigest: strings.Repeat("4", 64), OpaquePin: strings.Repeat("5", 64), RouteGeneration: strings.Repeat("6", 64), IndexRevision: 1}
			capability = sign("weknora-cap-v1", managedcapability.Claims{Issuer: "superwagie-knowledge-v1", Audience: "weknora", Binding: binding, IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(time.Minute).Unix()})
			repo := &refKnowledgeRepoStub{}
			queue := &recordManagedQueue{}
			service := newReferenceService(repo, &createKnowledgeTaskEnqueuerStub{})
			service.task = queue
			service.managedWorker = worker
			knowledge, err := service.CreateManagedKnowledgeFromPath(newCreateKnowledgeFileContext(), "kb-1", file, capability)
			require.NoError(t, err)
			var payload types.DocumentProcessPayload
			require.NoError(t, json.Unmarshal(queue.task.Payload(), &payload))
			require.Equal(t, binding.KnowledgeID, knowledge.ID)
			admission, err := worker.Prepare(context.Background(), payload)
			require.NoError(t, err)
			parsed, err := (&docparser.SimpleFormatReader{}).Read(admission.Context, &types.ReadRequest{FileName: payload.FileName, FileType: "txt", FileContent: admission.Snapshot})
			require.NoError(t, err)
			chunks := chunker.Split(parsed.MarkdownContent, chunker.DefaultConfig())
			require.Len(t, chunks, 1)
			content := buildKnowledgeIndexContent(knowledge, chunks[0].Content)
			client := openaiembeddings.New(openaiembeddings.Config{Endpoint: api.Endpoint{Model: managedcapability.EmbeddingModel, BaseURL: "https://invalid.test/v1"}, Retry: api.RetryPolicy{MaxRetries: 3}})
			embedder := pilotEmbedder{client: client}
			vectors := &pilotIndexRepo{}
			indexer := retriever.NewKVHybridRetrieveEngine(vectors, types.PostgresRetrieverEngineType)
			indexes := []*types.IndexInfo{{SourceID: "chunk", Content: content}}
			err = indexer.BatchIndex(admission.Context, embedder, indexes, []types.RetrieverType{types.VectorRetrieverType})
			if settled {
				require.NoError(t, err)
				require.EqualValues(t, 1, vectors.saves.Load())
				require.EqualValues(t, 1, dispatches.Load())
				err = indexer.BatchIndex(admission.Context, embedder, indexes, []types.RetrieverType{types.VectorRetrieverType})
				require.NoError(t, err)
				require.EqualValues(t, 2, vectors.saves.Load())
				require.EqualValues(t, 1, dispatches.Load())
				return
			}
			require.Error(t, err)
			require.Zero(t, vectors.saves.Load())
			require.EqualValues(t, 1, dispatches.Load())
			allowResult = true
			err = indexer.BatchIndex(admission.Context, embedder, indexes, []types.RetrieverType{types.VectorRetrieverType})
			require.NoError(t, err)
			require.EqualValues(t, 1, vectors.saves.Load())
			require.EqualValues(t, 1, dispatches.Load(), fmt.Sprintf("UNKNOWN must recover without redispatch"))
		})
	}
}

func TestPilotBindingKeyMismatchFailsClosed(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier, err := managedcapability.NewVerifier("issuer", "weknora", map[string]ed25519.PublicKey{"host-v1": pub}, time.Hour, time.Now)
	require.NoError(t, err)
	host, err := managedcapability.NewHostAuthority("http://127.0.0.1:12345/internal/knowledge-work/authorize", verifier, &http.Client{}, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "state.db")), &gorm.Config{})
	require.NoError(t, err)
	journal, err := managedjournal.Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	_, err = newPilotManagedWorker(db, verifier, host, journal, []byte("9876543210abcdef9876543210abcdef"))
	require.NoError(t, err)
	_, err = newPilotManagedWorker(db, verifier, host, journal, []byte("different-key-different-key-1234"))
	require.Error(t, err)
}

func TestManagedRequestProofIsConsumedOnceAcrossRestart(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	verifier, err := managedcapability.NewVerifier("issuer", "weknora", map[string]ed25519.PublicKey{"host-v1": pub}, time.Hour, time.Now)
	require.NoError(t, err)
	host, err := managedcapability.NewHostAuthority("http://127.0.0.1:12345/internal/knowledge-work/authorize", verifier, &http.Client{}, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "state.db")), &gorm.Config{})
	require.NoError(t, err)
	journal, err := managedjournal.Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	worker, err := newPilotManagedWorker(db, verifier, host, journal, []byte("9876543210abcdef9876543210abcdef"))
	require.NoError(t, err)
	body := []byte(`{"capability":"secret"}`)
	sum := sha256.Sum256(body)
	claims := managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: "/api/v1/managed", BodySHA256: hex.EncodeToString(sum[:]), Nonce: strings.Repeat("c", 64), WorkID: "work", ActorID: "actor", AccountID: "payer", IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(29 * time.Second).Unix()}
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	prefix := "weknora-request-v1.host-v1." + base64.RawURLEncoding.EncodeToString(raw)
	proof := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(prefix)))
	require.NoError(t, worker.acceptProof(context.Background(), "POST", claims.Path, body, proof, "work", "actor", "payer"))
	reopened, err := newPilotManagedWorker(db, verifier, host, journal, []byte("9876543210abcdef9876543210abcdef"))
	require.NoError(t, err)
	require.Error(t, reopened.acceptProof(context.Background(), "POST", claims.Path, body, proof, "work", "actor", "payer"))
}

func TestManagedRequestProofConcurrentReplayHasOneWinner(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	verifier, err := managedcapability.NewVerifier("issuer", "weknora", map[string]ed25519.PublicKey{"host-v1": pub}, time.Hour, time.Now)
	require.NoError(t, err)
	host, err := managedcapability.NewHostAuthority("http://127.0.0.1:12345/internal/knowledge-work/authorize", verifier, &http.Client{}, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "state.db")), &gorm.Config{})
	require.NoError(t, err)
	journal, err := managedjournal.Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	worker, err := newPilotManagedWorker(db, verifier, host, journal, []byte("9876543210abcdef9876543210abcdef"))
	require.NoError(t, err)
	body := []byte(`{"capability":"secret"}`)
	sum := sha256.Sum256(body)
	claims := managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: "/api/v1/managed", BodySHA256: hex.EncodeToString(sum[:]), Nonce: strings.Repeat("d", 64), WorkID: "work", ActorID: "actor", AccountID: "payer", IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix()}
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	prefix := "weknora-request-v1.host-v1." + base64.RawURLEncoding.EncodeToString(raw)
	proof := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(prefix)))
	results := make(chan error, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			results <- worker.acceptProof(context.Background(), "POST", claims.Path, body, proof, "work", "actor", "payer")
		}()
	}
	close(start)
	first, second := <-results, <-results
	require.NotEqual(t, first == nil, second == nil)
}
