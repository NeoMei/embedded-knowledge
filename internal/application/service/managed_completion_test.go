package service

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqliteRepo "github.com/Tencent/WeKnora/internal/application/repository/retriever/sqlite"
	"github.com/Tencent/WeKnora/internal/application/service/retriever"
	"github.com/Tencent/WeKnora/internal/infrastructure/chunker"
	"github.com/Tencent/WeKnora/internal/infrastructure/docparser"
	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/models/api/openaiembeddings"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	sqlitevec "github.com/asg017/sqlite-vec-go-bindings/cgo"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var completionVecOnce sync.Once

type completionFixture struct {
	t                 *testing.T
	db                *gorm.DB
	path              string
	worker            *pilotManagedWorker
	key               ed25519.PrivateKey
	verifier          *managedcapability.Verifier
	host              *managedcapability.HostAuthority
	binding           managedcapability.Binding
	search            managedcapability.SearchBinding
	document          []byte
	raw               []byte
	now               atomic.Int64
	dispatches        atomic.Int32
	reads             atomic.Int32
	callbacks         atomic.Int32
	denied            atomic.Bool
	pending           atomic.Bool
	duringRerank      func()
	readAssertionMode string
}

func (f *completionFixture) sign(kind string, v any) string {
	raw, e := json.Marshal(v)
	require.NoError(f.t, e)
	p := kind + ".host-v1." + base64.RawURLEncoding.EncodeToString(raw)
	return p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, []byte(p)))
}
func (f *completionFixture) open() {
	db, e := gorm.Open(sqlite.Open(f.path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(f.t, e)
	sql, e := db.DB()
	require.NoError(f.t, e)
	sql.SetMaxOpenConns(1)
	f.db = db
	j, e := managedjournal.Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(f.t, e)
	f.worker, e = newPilotManagedWorker(db, f.verifier, f.host, j, []byte("9876543210abcdef9876543210abcdef"))
	require.NoError(f.t, e)
}
func newCompletionFixture(t *testing.T) *completionFixture {
	t.Helper()
	completionVecOnce.Do(sqlitevec.Auto)
	f := &completionFixture{t: t, path: filepath.Join(t.TempDir(), "store.db"), document: []byte(strings.Repeat("a", 300))}
	f.now.Store(time.Now().Unix())
	f.pending.Store(true)
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	f.key = priv
	f.verifier, e = managedcapability.NewVerifier("issuer", "weknora", map[string]ed25519.PublicKey{"host-v1": pub}, time.Hour, func() time.Time { return time.Unix(f.now.Load(), 0) })
	require.NoError(t, e)
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	f.host, e = managedcapability.NewHostAuthority(server.URL+"/internal/knowledge-work/authorize", f.verifier, server.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	f.open()
	t.Cleanup(func() { db, _ := f.db.DB(); _ = db.Close() })
	for _, sql := range []string{
		`CREATE TABLE knowledge_bases (id TEXT PRIMARY KEY,tenant_id INTEGER,deleted_at DATETIME)`,
		`CREATE TABLE knowledges (id TEXT PRIMARY KEY,tenant_id INTEGER,knowledge_base_id TEXT,managed_work_id TEXT,parse_status TEXT,enable_status TEXT,pending_subtasks_count INTEGER,title TEXT,file_name TEXT,source TEXT,deleted_at DATETIME,updated_at DATETIME)`,
		`CREATE TABLE chunks (id TEXT PRIMARY KEY,tenant_id INTEGER,knowledge_id TEXT,knowledge_base_id TEXT,content TEXT,content_revision INTEGER,chunk_type TEXT,chunk_index INTEGER,is_enabled INTEGER,deleted_at DATETIME)`,
	} {
		require.NoError(t, f.db.Exec(sql).Error)
	}
	repo := sqliteRepo.NewSQLiteRetrieveEngineRepository(f.db)
	_ = repo
	f.binding = managedcapability.Binding{IndexBinding: managedcapability.IndexBinding{NamespaceID: strings.Repeat("1", 64), StorageID: f.worker.storage.StorageID, StorageGeneration: f.worker.storage.StorageGeneration, EmbeddingPolicyDigest: strings.Repeat("4", 64), OpaquePin: strings.Repeat("5", 64), RouteGeneration: strings.Repeat("6", 64), IndexRevision: 1}, TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", Purpose: "document-ingest", InputDigest: strings.Repeat("a", 64), EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace}
	vector := make([]float32, 1024)
	for i := range vector {
		vector[i] = float32(i+1) / 1024
	}
	f.raw, e = json.Marshal(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": vector}}})
	require.NoError(t, e)
	return f
}
func (f *completionFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.callbacks.Add(1)
	// This barrier uses the same production one-connection pool. A callback
	// made inside a transaction cannot acquire it and fails the request deadline.
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	var n int
	if f.db.WithContext(ctx).Raw("SELECT 1").Scan(&n).Error != nil {
		f.t.Error("callback attempted inside SQLite transaction")
		w.WriteHeader(503)
		return
	}
	if f.denied.Load() {
		w.WriteHeader(403)
		return
	}
	var req struct {
		Nonce     string          `json:"nonce"`
		WorkID    string          `json:"work_id"`
		CallID    string          `json:"call_id"`
		Content   string          `json:"content"`
		Scope     json.RawMessage `json:"scope"`
		Operation string          `json:"operation"`
	}
	body, err := io.ReadAll(r.Body)
	require.NoError(f.t, err)
	require.NoError(f.t, json.Unmarshal(body, &req))
	mac := hmac.New(sha256.New, []byte("0123456789abcdef0123456789abcdef"))
	sum := sha256.Sum256(body)
	_, err = fmt.Fprintf(mac, "weknora-callback-v2\n%s\n%s\n%x\n%s\n%s", r.Method, r.URL.Path, sum, req.Nonce, r.Header.Get("X-WeKnora-Worker-Time"))
	require.NoError(f.t, err)
	require.Equal(f.t, hex.EncodeToString(mac.Sum(nil)), r.Header.Get("X-WeKnora-Worker-Signature"))
	now := f.now.Load()
	send := func(kind string, claims any, content []byte) {
		out := map[string]string{"assertion": f.sign(kind, claims)}
		if content != nil {
			out["content"] = base64.StdEncoding.EncodeToString(content)
		}
		require.NoError(f.t, json.NewEncoder(w).Encode(out))
	}
	switch r.URL.Path {
	case "/internal/knowledge-work/authorize":
		send("weknora-auth-v1", managedcapability.ActiveClaims{Issuer: "issuer", Audience: "weknora", Binding: f.binding, Nonce: req.Nonce, IssuedAt: now, ExpiresAt: now + 30}, nil)
	case "/internal/knowledge-work/snapshot":
		send("weknora-snapshot-v1", managedcapability.SnapshotClaims{Issuer: "issuer", Audience: "weknora", Binding: f.binding, Nonce: req.Nonce, IssuedAt: now, ExpiresAt: now + 30, ContentSHA256: managedSHA(f.document)}, f.document)
	case "/internal/knowledge-work/dispatch":
		body, err := base64.StdEncoding.DecodeString(req.Content)
		require.NoError(f.t, err)
		var request struct {
			Input []string `json:"input"`
		}
		require.NoError(f.t, json.Unmarshal(body, &request))
		require.Equal(f.t, []string{"fixture.txt\n" + strings.TrimSpace(string(f.document))}, request.Input)
		f.dispatches.Add(1)
		w.WriteHeader(200)
	case "/internal/knowledge-work/result":
		f.reads.Add(1)
		send("weknora-result-v1", managedcapability.ResultClaims{Issuer: "issuer", Audience: "weknora", Binding: f.binding, Nonce: req.Nonce, IssuedAt: now, ExpiresAt: now + 30, CallID: req.CallID, AttemptID: "attempt", ProducerCredentialID: "producer", Model: f.binding.EmbeddingModel, Operation: "embedding", WireOperation: "embeddings.create", Status: "SETTLED", ContentSHA256: managedSHA(f.raw)}, f.raw)
	case "/internal/knowledge-work/storage-authorize", "/internal/knowledge-work/completed-authorize":
		var scope struct {
			Purpose string `json:"purpose"`
		}
		require.NoError(f.t, json.Unmarshal(req.Scope, &scope))
		kind := "completed-index-auth-v1"
		if r.URL.Path == "/internal/knowledge-work/storage-authorize" {
			kind = "managed-storage-auth-v1"
		}
		if scope.Purpose == "completion_discover" {
			if !f.pending.Load() {
				w.WriteHeader(403)
				return
			}
			kind = "completed-index-discover-auth-v1"
		}
		if f.readAssertionMode == "wrong_challenge" {
			req.Nonce = strings.Repeat("0", 64)
		}
		if f.readAssertionMode == "expired" {
			now -= 31
		}
		send(kind, struct {
			Scope     json.RawMessage `json:"scope"`
			Nonce     string          `json:"nonce"`
			IssuedAt  int64           `json:"issued_at"`
			ExpiresAt int64           `json:"expires_at"`
		}{req.Scope, req.Nonce, now, now + 30}, nil)
	case "/internal/knowledge-search/authorize":
		send("weknora-search-auth-v1", managedcapability.SearchActiveClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, Nonce: req.Nonce, IssuedAt: now, ExpiresAt: now + 30}, nil)
	case "/internal/knowledge-search/snapshot":
		q := []byte("query")
		send("weknora-search-snapshot-v1", managedcapability.SearchSnapshotClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, Nonce: req.Nonce, IssuedAt: now, ExpiresAt: now + 30, ContentSHA256: managedSHA(q)}, q)
	case "/internal/knowledge-search/dispatch":
		if req.Operation == "rerank" {
			body, err := base64.StdEncoding.DecodeString(req.Content)
			require.NoError(f.t, err)
			var request struct {
				Input struct {
					Documents []string `json:"documents"`
				} `json:"input"`
			}
			require.NoError(f.t, json.Unmarshal(body, &request))
			require.Equal(f.t, []string{string(f.document)}, request.Input.Documents, "rerank consumes the original chunk, not embedding text")
		}
		f.dispatches.Add(1)
		if req.Operation == "rerank" && f.duringRerank != nil {
			f.duringRerank()
		}
		w.WriteHeader(200)
	case "/internal/knowledge-search/result":
		f.reads.Add(1)
		raw := f.raw
		model, wire := f.search.EmbeddingModel, "embeddings.create"
		if req.Operation == "rerank" {
			model, wire = f.search.RerankModel, "rerank.create"
			raw = []byte(`{"output":{"results":[{"index":0,"relevance_score":0.9}]}}`)
		}
		send("weknora-search-result-v1", managedcapability.SearchResultClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, Nonce: req.Nonce, IssuedAt: now, ExpiresAt: now + 30, CallID: req.CallID, Model: model, Operation: req.Operation, WireOperation: wire, Status: "SETTLED", ContentSHA256: managedSHA(raw)}, raw)
	default:
		f.t.Errorf("unexpected callback %s", r.URL.Path)
		w.WriteHeader(404)
	}
}
func (f *completionFixture) ingest() {
	t := f.t
	ctx := context.Background()
	now := f.now.Load()
	token := f.sign("weknora-cap-v1", managedcapability.Claims{Issuer: "issuer", Audience: "weknora", Binding: f.binding, IssuedAt: now, ExpiresAt: now + 60})
	_, err := f.worker.Register(ctx, 1, "kb", "fixture.txt", token)
	require.NoError(t, err)
	require.NoError(t, f.db.Exec("INSERT INTO knowledge_bases(id,tenant_id) VALUES('kb',1)").Error)
	require.NoError(t, f.db.Exec("INSERT INTO knowledges(id,tenant_id,knowledge_base_id,managed_work_id,parse_status,enable_status,pending_subtasks_count,title,file_name,source) VALUES('doc',1,'kb','work','processing','disabled',0,'fixture.txt','fixture.txt','file')").Error)
	admission, err := f.worker.Prepare(ctx, types.DocumentProcessPayload{TenantID: 1, KnowledgeBaseID: "kb", KnowledgeID: "doc", ManagedWorkID: "work", FileName: "fixture.txt"})
	require.NoError(t, err)
	parsed, err := (&docparser.SimpleFormatReader{}).Read(admission.Context, &types.ReadRequest{FileName: "fixture.txt", FileType: "txt", FileContent: admission.Snapshot})
	require.NoError(t, err)
	chunks := chunker.Split(chunker.NormalizeLineEndings(parsed.MarkdownContent), chunker.DefaultConfig())
	require.Len(t, chunks, 1)
	chunk := types.Chunk{Content: chunks[0].Content, ContextHeader: chunks[0].ContextHeader}
	content := buildKnowledgeIndexContent(&types.Knowledge{Title: "fixture.txt"}, chunk.EmbeddingContent())
	require.NoError(t, f.db.Exec("INSERT INTO chunks(id,tenant_id,knowledge_id,knowledge_base_id,content,content_revision,chunk_type,chunk_index,is_enabled) VALUES('chunk',1,'doc','kb',?,0,'text',0,1)", chunk.Content).Error)
	repo := sqliteRepo.NewSQLiteRetrieveEngineRepository(f.db)
	indexer := retriever.NewKVHybridRetrieveEngine(repo, types.SQLiteRetrieverEngineType)
	require.NoError(t, indexer.BatchIndex(admission.Context, pilotEmbedder{client: newCompletionEmbedClient()}, []*types.IndexInfo{{SourceID: "chunk", SourceType: types.ChunkSourceType, ChunkID: "chunk", KnowledgeID: "doc", KnowledgeBaseID: "kb", Content: content, IsEnabled: true}}, []types.RetrieverType{types.VectorRetrieverType}))
	require.NoError(t, f.worker.installCompletionGuards())
}
func (f *completionFixture) finalize() error {
	return f.db.Transaction(func(tx *gorm.DB) error { return f.worker.FinalizeManagedIndexTx(context.Background(), tx, "work") })
}
func (f *completionFixture) status(kind string, claims any) (*ManagedStatus, error) {
	token := f.sign(kind, claims)
	body, _ := json.Marshal(map[string]string{"capability": token})
	nonce, e := managedRandom()
	require.NoError(f.t, e)
	now := f.now.Load()
	path := "/api/v1/knowledge-bases/kb/knowledge/managed-status"
	proof := f.sign("weknora-request-v1", managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: path, BodySHA256: managedSHA(body), Nonce: nonce, WorkID: "work", ActorID: "actor", AccountID: "payer", IssuedAt: now, ExpiresAt: now + 30})
	switch kind {
	case "completed-index-discover-v1":
		return f.worker.discoveryStatus(context.Background(), 1, "kb", "POST", path, body, token, proof)
	case "managed-storage-v1":
		return f.worker.storageStatus(context.Background(), 1, "kb", "POST", path, body, token, proof)
	default:
		return f.worker.completedStatus(context.Background(), 1, "kb", "POST", path, body, token, proof)
	}
}
func (f *completionFixture) discover() managedcapability.CompletionDiscover {
	now := f.now.Load()
	return managedcapability.CompletionDiscover{Version: "completed-index-discover-v1", Purpose: "completion_discover", Binding: f.binding, SnapshotSHA256: managedSHA(f.document), HostBootID: strings.Repeat("8", 64), WorkerBootID: f.worker.workerBootID, IssuedAt: now, ExpiresAt: now + 30}
}
func (f *completionFixture) use() managedcapability.CompletedUse {
	var row managedCompletion
	require.NoError(f.t, f.db.First(&row, "work_id = 'work'").Error)
	b := f.binding
	now := f.now.Load()
	return managedcapability.CompletedUse{Version: "completed-index-use-v1", Purpose: "completed_index_read", NamespaceID: b.NamespaceID, TenantID: b.TenantID, ActorID: b.ActorID, AccountID: b.AccountID, KnowledgeBaseID: b.KnowledgeBaseID, KnowledgeID: b.KnowledgeID, WorkID: b.WorkID, StorageID: b.StorageID, StorageGeneration: b.StorageGeneration, IndexRevision: 1, CompletionDigest: managedSHA([]byte(row.Payload)), HostBootID: strings.Repeat("8", 64), WorkerBootID: f.worker.workerBootID, IssuedAt: now, ExpiresAt: now + 30}
}

func TestManagedCompletionRealSQLiteRestartAfterRetention(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	require.NoError(t, f.finalize())
	beforeDispatch, beforeRead := f.dispatches.Load(), f.reads.Load()
	require.EqualValues(t, 1, beforeDispatch)
	oldBoot := f.worker.workerBootID
	db, _ := f.db.DB()
	require.NoError(t, db.Close())
	f.now.Add(7200)
	f.open()
	require.NotEqual(t, oldBoot, f.worker.workerBootID)
	// Old token has expired and journal result storage is removed entirely. Ready
	// verification uses only MACed completion + actual rows + current authority.
	require.NoError(t, f.db.Exec("DELETE FROM managed_index_producers").Error)
	require.NoError(t, f.db.Exec("DELETE FROM managed_model_requests").Error)
	reply, err := f.status("completed-index-discover-v1", f.discover())
	require.NoError(t, err)
	require.Equal(t, "ready", reply.Discovery.State)
	reply, err = f.status("completed-index-use-v1", f.use())
	require.NoError(t, err)
	require.Equal(t, "ready", reply.Completion.State)
	require.Equal(t, beforeDispatch, f.dispatches.Load())
	require.Equal(t, beforeRead, f.reads.Load())
	f.denied.Store(true)
	_, err = f.status("completed-index-use-v1", f.use())
	require.Error(t, err)
}
func TestManagedCompletionRejectsWrongStoredReferences(t *testing.T) {
	for _, mode := range []string{"absent_vector", "wrong_vector_same_raw_sha", "wrong_source", "wrong_namespace", "wrong_chunk", "partial_rollback", "nonfinite"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompletionFixture(t)
			f.ingest()
			switch mode {
			case "absent_vector":
				require.NoError(t, f.db.Exec("DELETE FROM vec_embeddings_1024").Error)
			case "wrong_vector_same_raw_sha":
				v := make([]byte, 4096)
				require.NoError(t, f.db.Exec("UPDATE vec_embeddings_1024 SET embedding=?", v).Error)
			case "wrong_source":
				require.NoError(t, f.db.Exec("UPDATE lite_embeddings SET source_id='other'").Error)
			case "wrong_namespace":
				var p managedProducer
				require.NoError(t, f.db.First(&p).Error)
				var facts managedProducerFacts
				require.NoError(t, json.Unmarshal([]byte(p.Payload), &facts))
				facts.Binding.NamespaceID = strings.Repeat("2", 64)
				raw, _ := json.Marshal(facts)
				require.NoError(t, f.db.Model(&p).Updates(map[string]any{"payload": string(raw), "mac": f.worker.seal("managed-producer-v1", raw)}).Error)
			case "wrong_chunk":
				require.NoError(t, f.db.Exec("UPDATE chunks SET content='changed'").Error)
			case "nonfinite":
				v := make([]byte, 4096)
				v[2] = 128
				v[3] = 127
				require.NoError(t, f.db.Exec("UPDATE vec_embeddings_1024 SET embedding=?", v).Error)
			case "partial_rollback":
				require.NoError(t, f.db.Exec("CREATE TRIGGER fail_ready BEFORE UPDATE OF parse_status ON knowledges BEGIN SELECT RAISE(ABORT,'fixture rollback'); END").Error)
			}
			require.Error(t, f.finalize())
			var n int64
			require.NoError(t, f.db.Model(&managedCompletion{}).Count(&n).Error)
			require.Zero(t, n)
			var state string
			require.NoError(t, f.db.Raw("SELECT parse_status FROM knowledges WHERE id='doc'").Scan(&state).Error)
			require.Equal(t, "processing", state)
		})
	}
}
func TestManagedCompletionMutationInvalidatesAndUseScope(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	for _, change := range []func(*managedcapability.CompletedUse){func(c *managedcapability.CompletedUse) { c.ActorID = "other" }, func(c *managedcapability.CompletedUse) { c.AccountID = "other" }, func(c *managedcapability.CompletedUse) { c.NamespaceID = strings.Repeat("0", 64) }, func(c *managedcapability.CompletedUse) { c.StorageGeneration = strings.Repeat("0", 64) }, func(c *managedcapability.CompletedUse) { c.WorkerBootID = strings.Repeat("0", 64) }, func(c *managedcapability.CompletedUse) { c.ExpiresAt = c.IssuedAt + 31 }, func(c *managedcapability.CompletedUse) { c.IndexRevision++ }} {
		c := f.use()
		change(&c)
		_, err := f.status("completed-index-use-v1", c)
		require.Error(t, err)
	}
	f.pending.Store(false)
	_, err := f.status("completed-index-discover-v1", f.discover())
	require.Error(t, err)
	f.pending.Store(true)
	require.NoError(t, f.db.Exec("UPDATE chunks SET content=content WHERE id='chunk'").Error)
	var row managedCompletion
	require.NoError(t, f.db.First(&row).Error)
	require.True(t, row.Invalid)
	require.EqualValues(t, 2, row.Revision)
	_, err = f.status("completed-index-use-v1", f.use())
	require.Error(t, err)
}
func TestManagedCompletionMissingIdentityFailsClosed(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	require.NoError(t, f.db.Exec("DELETE FROM managed_store_meta").Error)
	_, err := newPilotManagedWorker(f.db, f.verifier, f.host, f.worker.journal, []byte("9876543210abcdef9876543210abcdef"))
	require.Error(t, err)
}

func TestManagedCompletionMissingOrMismatchedDurableStateFailsClosed(t *testing.T) {
	for _, mode := range []string{"wrong_key", "missing_key", "missing_completion", "changed_generation", "completion_rollback"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompletionFixture(t)
			f.ingest()
			require.NoError(t, f.finalize())
			use := f.use()
			beforeDispatch, beforeRead := f.dispatches.Load(), f.reads.Load()
			switch mode {
			case "wrong_key", "missing_key":
				key := []byte(strings.Repeat("0", 32))
				if mode == "missing_key" {
					key = nil
				}
				_, err := newPilotManagedWorker(f.db, f.verifier, f.host, f.worker.journal, key)
				require.Error(t, err)
			case "missing_completion":
				require.NoError(t, f.db.Exec("DELETE FROM managed_index_completions").Error)
			case "changed_generation":
				require.NoError(t, f.db.Exec("UPDATE managed_store_meta SET storage_generation=?", strings.Repeat("0", 64)).Error)
			case "completion_rollback":
				require.NoError(t, f.db.Exec("UPDATE managed_index_completions SET revision=0").Error)
			}
			if mode != "wrong_key" && mode != "missing_key" {
				_, err := f.status("completed-index-use-v1", use)
				require.Error(t, err)
			}
			require.Equal(t, beforeDispatch, f.dispatches.Load())
			require.Equal(t, beforeRead, f.reads.Load())
		})
	}
}

func TestManagedCompletionReadRequiresFreshCurrentHostAssertion(t *testing.T) {
	for _, mode := range []string{"wrong_challenge", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompletionFixture(t)
			f.ingest()
			require.NoError(t, f.finalize())
			f.readAssertionMode = mode
			beforeDispatch, beforeRead := f.dispatches.Load(), f.reads.Load()
			_, err := f.status("completed-index-use-v1", f.use())
			require.Error(t, err)
			_, err = f.status("completed-index-discover-v1", f.discover())
			require.Error(t, err)
			require.Equal(t, beforeDispatch, f.dispatches.Load())
			require.Equal(t, beforeRead, f.reads.Load())
		})
	}
}

func newCompletionEmbedClient() *openaiembeddings.Client {
	return openaiembeddings.New(openaiembeddings.Config{Endpoint: api.Endpoint{Model: managedcapability.EmbeddingModel, BaseURL: "https://invalid.test/v1"}, Retry: api.RetryPolicy{MaxRetries: 0}})
}

type completionKnowledgeRepo struct {
	interfaces.KnowledgeRepository
	db *gorm.DB
}

func (r completionKnowledgeRepo) GetKnowledgeByID(ctx context.Context, tenant uint64, id string) (*types.Knowledge, error) {
	var k types.Knowledge
	err := r.db.WithContext(ctx).Where("tenant_id=? AND id=?", tenant, id).First(&k).Error
	return &k, err
}
func (r completionKnowledgeRepo) GetKnowledgeByIDOnly(ctx context.Context, id string) (*types.Knowledge, error) {
	var k types.Knowledge
	err := r.db.WithContext(ctx).Where("id=?", id).First(&k).Error
	return &k, err
}

type completionPostprocessKB struct {
	interfaces.KnowledgeBaseService
	svc *knowledgeBaseService
	db  *gorm.DB
}

func (s completionPostprocessKB) GetKnowledgeBaseByIDOnly(ctx context.Context, id string) (*types.KnowledgeBase, error) {
	var kb types.KnowledgeBase
	err := s.db.WithContext(ctx).Where("id=?", id).First(&kb).Error
	return &kb, err
}
func (s completionPostprocessKB) CompleteManagedIndex(ctx context.Context, work string) error {
	return s.svc.CompleteManagedIndex(ctx, work)
}

func TestManagedCompletionPostprocessCommitsRealIndexAndReadyTogether(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	svc := KnowledgePostProcessService{knowledgeRepo: completionKnowledgeRepo{db: f.db}, kbService: completionPostprocessKB{svc: &knowledgeBaseService{managedWorker: f.worker}, db: f.db}}
	raw, err := json.Marshal(types.KnowledgePostProcessPayload{TenantID: 1, KnowledgeBaseID: "kb", KnowledgeID: "doc"})
	require.NoError(t, err)
	for range 2 {
		require.NoError(t, svc.Handle(context.Background(), asynq.NewTask(types.TypeKnowledgePostProcess, raw)))
	}
	reply, err := f.status("completed-index-use-v1", f.use())
	require.NoError(t, err)
	require.Equal(t, "ready", reply.Completion.State)
	require.EqualValues(t, 1, f.dispatches.Load())
}
func TestManagedCompletionSearchSingleConnectionAndStaleBarrier(t *testing.T) {
	for _, mode := range []string{"active", "mutation_during_rerank", "revoked_during_rerank", "expired_during_rerank"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompletionFixture(t)
			f.ingest()
			require.NoError(t, f.finalize())
			use := f.use()
			f.search = managedcapability.SearchBinding{IndexBinding: f.binding.IndexBinding, CompletionDigest: use.CompletionDigest, IndexWorkID: "work", TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "search-grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: f.binding.EmbeddingModel, EmbeddingSpace: f.binding.EmbeddingSpace, RerankModel: "qwen3-rerank"}
			now := f.now.Load()
			token := f.sign("weknora-search-v1", managedcapability.SearchClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, IssuedAt: now, ExpiresAt: now + 30})
			f.duringRerank = func() {
				switch mode {
				case "mutation_during_rerank":
					require.NoError(t, f.db.Exec("UPDATE chunks SET content='changed'").Error)
				case "revoked_during_rerank":
					f.denied.Store(true)
				case "expired_during_rerank":
					f.now.Add(31)
				}
			}
			svc := &knowledgeBaseService{managedWorker: f.worker, kgRepo: completionKnowledgeRepo{db: f.db}}
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1)), 5*time.Second)
			defer cancel()
			_, decodeErr := f.verifier.DecodeSearch(token)
			require.NoError(t, decodeErr, "search envelope")
			require.NoError(t, f.host.SearchCheck(ctx, f.search), "search authority")
			_, lookupErr := f.worker.lookup(ctx, f.db, "work")
			require.NoError(t, lookupErr, "registration")
			require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
				_, _, e := f.worker.ReadCompletedIndexTx(ctx, tx, "work", 1, use.CompletionDigest)
				return e
			}), "completion")
			_, snapshotErr := f.host.SearchSnapshot(ctx, f.search)
			require.NoError(t, snapshotErr, "query snapshot")
			result, err := svc.ManagedHybridSearch(ctx, "kb", token)
			if mode == "active" {
				require.NoError(t, err)
				require.Len(t, result.Results, 1)
				require.Equal(t, string(f.document), result.Results[0].Content)
				require.Equal(t, "doc", result.Results[0].KnowledgeID)
				result, err = svc.ManagedHybridSearch(ctx, "kb", token)
				require.NoError(t, err)
				require.Len(t, result.Results, 1)
			} else {
				require.Error(t, err)
				require.Nil(t, result)
			}
			require.EqualValues(t, 3, f.dispatches.Load(), "one ingest and exactly one query embedding/rerank; duplicate work never redispatches")
		})
	}
}

func TestManagedSearchResponseEnvelopeConsumesProofAndAuthenticatesExactPayload(t *testing.T) {
	goldenRaw, err := os.ReadFile("testdata/managed-search-response-golden-v1.json")
	require.NoError(t, err)
	var golden struct {
		CallbackKey string `json:"callback_key_fixture_only"`
		Response    struct {
			Data struct {
				Payload string `json:"payload"`
				MAC     string `json:"mac"`
			} `json:"data"`
		} `json:"response"`
		RawPayload string `json:"raw_payload_utf8"`
	}
	require.NoError(t, json.Unmarshal(goldenRaw, &golden))
	fixtureKey := []byte(golden.CallbackKey)
	goldenPayload, err := base64.StdEncoding.DecodeString(golden.Response.Data.Payload)
	require.NoError(t, err)
	require.Equal(t, golden.RawPayload, string(goldenPayload))
	derive := hmac.New(sha256.New, fixtureKey)
	_, _ = derive.Write([]byte("managed-search-response-v1"))
	fixtureMAC := hmac.New(sha256.New, derive.Sum(nil))
	_, err = fixtureMAC.Write(goldenPayload)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(fixtureMAC.Sum(nil)), golden.Response.Data.MAC)

	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	now := f.now.Load()
	use := f.use()
	f.search = managedcapability.SearchBinding{IndexBinding: f.binding.IndexBinding, CompletionDigest: use.CompletionDigest, IndexWorkID: "work", TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "search-grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: f.binding.EmbeddingModel, EmbeddingSpace: f.binding.EmbeddingSpace, RerankModel: "qwen3-rerank"}
	capability := f.sign("weknora-search-v1", managedcapability.SearchClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, IssuedAt: now, ExpiresAt: now + 30})
	body, err := json.Marshal(struct {
		Capability string `json:"capability"`
	}{capability})
	require.NoError(t, err)
	path := "/api/v1/knowledge-bases/kb/managed-hybrid-search"
	nonce := strings.Repeat("c", 64)
	proof := f.sign("weknora-request-v1", managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: path, BodySHA256: managedSHA(body), Nonce: nonce, WorkID: f.search.WorkID, ActorID: f.search.ActorID, AccountID: f.search.AccountID, IssuedAt: now, ExpiresAt: now + 30})
	svc := &knowledgeBaseService{managedWorker: f.worker, kgRepo: completionKnowledgeRepo{db: f.db}}
	ctx := context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1))
	wrongBody := append(append([]byte(nil), body...), ' ')
	_, err = svc.ManagedHybridSearchWithEvidence(ctx, 1, "kb", "POST", path, wrongBody, capability, proof)
	require.Error(t, err, "proof body digest mismatch must fail before paid retrieval")
	require.EqualValues(t, 1, f.dispatches.Load(), "invalid proof cannot add any paid query calls")
	response, err := svc.ManagedHybridSearchWithEvidence(ctx, 1, "kb", "POST", path, body, capability, proof)
	require.NoError(t, err)
	require.NotEmpty(t, response.Payload)
	payloadRaw, err := base64.StdEncoding.DecodeString(response.Payload)
	require.NoError(t, err)
	require.LessOrEqual(t, len(payloadRaw), managedSearchResponseMaxBytes)
	require.Equal(t, f.host.SearchResponseMAC(payloadRaw), response.MAC)
	var payload managedSearchResponsePayload
	require.NoError(t, json.Unmarshal(payloadRaw, &payload))
	require.Equal(t, "managed-search-response-v1", payload.Version)
	require.Equal(t, f.search, payload.Scope)
	require.Equal(t, nonce, payload.Nonce)
	require.Equal(t, f.worker.workerBootID, payload.WorkerBootID)
	require.LessOrEqual(t, payload.ExpiresAt, now+30)
	resultRaw, err := base64.StdEncoding.DecodeString(payload.ResultBase64)
	require.NoError(t, err)
	require.Equal(t, managedSHA(resultRaw), payload.ContentSHA256)
	require.EqualValues(t, 3, f.dispatches.Load(), "one ingest embedding, one query embedding and one rerank")
	_, err = svc.ManagedHybridSearchWithEvidence(ctx, 1, "kb", "POST", path, body, capability, proof)
	require.Error(t, err, "request nonce replay must be refused")
	require.EqualValues(t, 3, f.dispatches.Load(), "a replay cannot repeat paid work")
	f.denied.Store(true)
	staleProof := f.sign("weknora-request-v1", managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: path, BodySHA256: managedSHA(body), Nonce: strings.Repeat("d", 64), WorkID: f.search.WorkID, ActorID: f.search.ActorID, AccountID: f.search.AccountID, IssuedAt: now, ExpiresAt: now + 30})
	_, err = svc.ManagedHybridSearchWithEvidence(ctx, 1, "kb", "POST", path, body, capability, staleProof)
	require.Error(t, err, "stale host authority must fail closed")
	require.EqualValues(t, 3, f.dispatches.Load(), "stale authority cannot reach paid retrieval")
}

func TestManagedSearchResponseRejectsLateReferenceMutationBeforeSigning(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	use := f.use()
	f.search = managedcapability.SearchBinding{IndexBinding: f.binding.IndexBinding, CompletionDigest: use.CompletionDigest, IndexWorkID: "work", TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "search-grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: f.binding.EmbeddingModel, EmbeddingSpace: f.binding.EmbeddingSpace, RerankModel: "qwen3-rerank"}
	var checks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/knowledge-search/authorize" && checks.Add(1) == 10 {
			require.NoError(t, f.db.Exec("UPDATE chunks SET content='changed after retrieval' WHERE id = ?", "chunk").Error)
		}
		f.serve(w, r)
	}))
	t.Cleanup(server.Close)
	var err error
	f.host, err = managedcapability.NewHostAuthority(server.URL+"/internal/knowledge-work/authorize", f.verifier, server.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	f.worker.host = f.host

	now := f.now.Load()
	capability := f.sign("weknora-search-v1", managedcapability.SearchClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, IssuedAt: now, ExpiresAt: now + 30})
	body, err := json.Marshal(struct {
		Capability string `json:"capability"`
	}{capability})
	require.NoError(t, err)
	path := "/api/v1/knowledge-bases/kb/managed-hybrid-search"
	proof := f.sign("weknora-request-v1", managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: path, BodySHA256: managedSHA(body), Nonce: strings.Repeat("e", 64), WorkID: f.search.WorkID, ActorID: f.search.ActorID, AccountID: f.search.AccountID, IssuedAt: now, ExpiresAt: now + 30})
	svc := &knowledgeBaseService{managedWorker: f.worker, kgRepo: completionKnowledgeRepo{db: f.db}}
	ctx := context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1))
	response, err := svc.ManagedHybridSearchWithEvidence(ctx, 1, "kb", "POST", path, body, capability, proof)
	require.EqualValues(t, 10, checks.Load(), "mutation is injected in the wrapper's final asynchronous authority check")
	require.Error(t, err, "changed references cannot receive a signed success")
	require.Nil(t, response)
	require.EqualValues(t, 3, f.dispatches.Load(), "only ingest embedding, query embedding, and rerank may dispatch")
	_, err = svc.ManagedHybridSearchWithEvidence(ctx, 1, "kb", "POST", path, body, capability, proof)
	require.Error(t, err, "failed response proof remains consumed")
	require.EqualValues(t, 3, f.dispatches.Load(), "failure and replay cannot add paid dispatches")
}

func TestManagedSearchResponseRejectsExpiryAtFinalAuthorityCheck(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	use := f.use()
	f.search = managedcapability.SearchBinding{IndexBinding: f.binding.IndexBinding, CompletionDigest: use.CompletionDigest, IndexWorkID: "work", TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "search-grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: f.binding.EmbeddingModel, EmbeddingSpace: f.binding.EmbeddingSpace, RerankModel: "qwen3-rerank"}
	var checks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/knowledge-search/authorize" && checks.Add(1) == 10 {
			f.now.Add(31)
		}
		f.serve(w, r)
	}))
	t.Cleanup(server.Close)
	var err error
	f.host, err = managedcapability.NewHostAuthority(server.URL+"/internal/knowledge-work/authorize", f.verifier, server.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	f.worker.host = f.host

	now := f.now.Load()
	capability := f.sign("weknora-search-v1", managedcapability.SearchClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, IssuedAt: now, ExpiresAt: now + 30})
	body, err := json.Marshal(struct {
		Capability string `json:"capability"`
	}{capability})
	require.NoError(t, err)
	path := "/api/v1/knowledge-bases/kb/managed-hybrid-search"
	proof := f.sign("weknora-request-v1", managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: path, BodySHA256: managedSHA(body), Nonce: strings.Repeat("f", 64), WorkID: f.search.WorkID, ActorID: f.search.ActorID, AccountID: f.search.AccountID, IssuedAt: now, ExpiresAt: now + 30})
	svc := &knowledgeBaseService{managedWorker: f.worker, kgRepo: completionKnowledgeRepo{db: f.db}}
	ctx := context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1))
	response, err := svc.ManagedHybridSearchWithEvidence(ctx, 1, "kb", "POST", path, body, capability, proof)
	require.EqualValues(t, 10, checks.Load())
	require.Error(t, err, "expired signed windows cannot be used for response signing")
	require.Nil(t, response)
	require.EqualValues(t, 3, f.dispatches.Load(), "expiry detection does not repeat a query or add dispatches")
}

func TestManagedCompletionUseNonceMACAndStorageHandshake(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	now := f.now.Load()
	storage := managedcapability.StorageRequest{Version: "managed-storage-v1", NamespaceID: f.binding.NamespaceID, TenantID: 1, ActorID: "actor", AccountID: "payer", KnowledgeBaseID: "kb", WorkID: "work", HostBootID: strings.Repeat("8", 64), IssuedAt: now, ExpiresAt: now + 30}
	reply, err := f.status("managed-storage-v1", storage)
	require.NoError(t, err)
	require.Equal(t, f.worker.storage.StorageID, reply.Storage.StorageID)
	require.Equal(t, f.worker.workerBootID, reply.Storage.WorkerBootID)
	use := f.use()
	token := f.sign("completed-index-use-v1", use)
	body, _ := json.Marshal(map[string]string{"capability": token})
	nonce := strings.Repeat("e", 64)
	path := "/api/v1/knowledge-bases/kb/knowledge/managed-status"
	proof := f.sign("weknora-request-v1", managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: path, BodySHA256: managedSHA(body), Nonce: nonce, WorkID: "work", ActorID: "actor", AccountID: "payer", IssuedAt: now, ExpiresAt: now + 30})
	reply, err = f.worker.completedStatus(context.Background(), 1, "kb", "POST", path, body, token, proof)
	require.NoError(t, err)
	mac := reply.Completion.MAC
	reply.Completion.MAC = ""
	raw, _ := json.Marshal(reply.Completion)
	require.Equal(t, f.host.CompletionResponseMAC(raw), mac)
	require.Equal(t, nonce, reply.Completion.Nonce)
	_, err = f.worker.completedStatus(context.Background(), 1, "kb", "POST", path, body, token, proof)
	require.Error(t, err)
	require.NoError(t, f.db.Model(&managedCompletion{}).Where("work_id='work'").Update("mac", strings.Repeat("0", 64)).Error)
	_, err = f.status("completed-index-use-v1", use)
	require.Error(t, err)
}
func TestManagedCompletionStoredVectorSwapAfterReady(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	use := f.use()
	// Raw vec0 corruption bypasses repository mutation hooks. Actual-byte
	// revalidation must still reject it even though reference IDs and SHA strings
	// in completion and producer records are unchanged.
	vector := make([]byte, 4096)
	require.NoError(t, f.db.Exec("UPDATE vec_embeddings_1024 SET embedding=?", vector).Error)
	_, err := f.status("completed-index-use-v1", use)
	require.Error(t, err)
}

func TestManagedCompletionRefusesNonVec0TableWithExactBytes(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	var stored struct{ Embedding []byte }
	require.NoError(t, f.db.Raw("SELECT embedding FROM vec_embeddings_1024 WHERE rowid=1").Scan(&stored).Error)
	require.NoError(t, f.db.Exec("DROP TABLE vec_embeddings_1024").Error)
	require.NoError(t, f.db.Exec("CREATE TABLE vec_embeddings_1024(embedding BLOB)").Error)
	require.NoError(t, f.db.Exec("INSERT INTO vec_embeddings_1024(rowid,embedding) VALUES(1,?)", stored.Embedding).Error)
	require.Error(t, f.finalize(), "ordinary BLOB tables are not an actual vec0 index")
}

func TestManagedEmbeddingVectorRejectsQuotedNumbers(t *testing.T) {
	vector := make([]any, 1024)
	for i := range vector {
		vector[i] = "0.5"
	}
	raw, err := json.Marshal(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": vector}}})
	require.NoError(t, err)
	_, err = managedVector(raw)
	require.Error(t, err, "embedding elements must be JSON numbers")
}
func TestManagedCompletionVectorDeleteInvalidatesInSameTransaction(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	repo := sqliteRepo.NewSQLiteRetrieveEngineRepository(f.db)
	require.NoError(t, repo.DeleteByChunkIDList(context.Background(), []string{"chunk"}, 1024, ""))
	var row managedCompletion
	require.NoError(t, f.db.First(&row).Error)
	require.True(t, row.Invalid)
	require.EqualValues(t, 2, row.Revision)
}

func TestManagedCompletionVectorDeleteFailureRollsBackInvalidation(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	use := f.use()
	require.NoError(t, f.db.Exec("CREATE TRIGGER reject_managed_delete BEFORE DELETE ON lite_embeddings BEGIN SELECT RAISE(ABORT,'fixture rollback'); END").Error)
	repo := sqliteRepo.NewSQLiteRetrieveEngineRepository(f.db)
	require.Error(t, repo.DeleteByChunkIDList(context.Background(), []string{"chunk"}, 1024, ""))
	var row managedCompletion
	require.NoError(t, f.db.First(&row).Error)
	require.False(t, row.Invalid)
	require.EqualValues(t, 1, row.Revision)
	reply, err := f.status("completed-index-use-v1", use)
	require.NoError(t, err)
	require.Equal(t, "ready", reply.Completion.State)
}
func TestManagedCompletionFixedJSONMACContracts(t *testing.T) {
	raw, err := os.ReadFile("../../managedcapability/testdata/completion-contract-v1.json")
	require.NoError(t, err)
	var fixture struct {
		Replies struct {
			Storage  ManagedStorageReply    `json:"storage"`
			Discover ManagedDiscoveryReply  `json:"discover"`
			Use      ManagedCompletionReply `json:"use"`
		} `json:"replies"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixture))
	f := newCompletionFixture(t)
	mac := fixture.Replies.Storage.MAC
	fixture.Replies.Storage.MAC = ""
	raw, err = json.Marshal(fixture.Replies.Storage)
	require.NoError(t, err)
	require.Equal(t, mac, f.host.CompletionResponseMAC(raw))
	mac = fixture.Replies.Discover.MAC
	fixture.Replies.Discover.MAC = ""
	raw, err = json.Marshal(fixture.Replies.Discover)
	require.NoError(t, err)
	require.Equal(t, mac, f.host.CompletionResponseMAC(raw))
	mac = fixture.Replies.Use.MAC
	fixture.Replies.Use.MAC = ""
	raw, err = json.Marshal(fixture.Replies.Use)
	require.NoError(t, err)
	require.Equal(t, mac, f.host.CompletionResponseMAC(raw))
}
