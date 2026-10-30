package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type managedStoreMeta struct {
	ID                int `gorm:"primaryKey"`
	StorageID         string
	StorageGeneration string
	MAC               string
}

func (managedStoreMeta) TableName() string { return "managed_store_meta" }

type managedProducer struct {
	WorkID  string `gorm:"primaryKey"`
	Payload string
	MAC     string
}

func (managedProducer) TableName() string { return "managed_index_producers" }

type managedCompletion struct {
	WorkID      string `gorm:"primaryKey"`
	KnowledgeID string `gorm:"uniqueIndex"`
	Revision    int64
	Invalid     bool
	Payload     string
	MAC         string
}

func (managedCompletion) TableName() string { return "managed_index_completions" }

type managedProducerFacts struct {
	Binding              managedcapability.Binding `json:"binding"`
	CallID               string                    `json:"call_id"`
	AttemptID            string                    `json:"attempt_id"`
	ProducerCredentialID string                    `json:"producer_credential_id"`
	SnapshotSHA256       string                    `json:"snapshot_sha256"`
	InputSHA256          string                    `json:"input_sha256"`
	RawResultSHA256      string                    `json:"raw_result_sha256"`
	Float32SHA256        string                    `json:"float32_sha256"`
	Vector               []byte                    `json:"vector_float32_le"`
}
type managedCompletionFacts struct {
	Producer        managedProducerFacts `json:"producer"`
	ReferenceDigest string               `json:"reference_digest"`
	ChunkID         string               `json:"chunk_id"`
	SourceID        string               `json:"source_id"`
	EmbeddingID     uint64               `json:"embedding_id"`
}
type managedReferences struct {
	Chunk       types.Chunk
	Knowledge   types.Knowledge
	EmbeddingID uint64
	SourceID    string
	Vector      []byte
	Content     string
}

func managedSHA(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func managedRandom() (string, error) {
	var b [32]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func (w *pilotManagedWorker) seal(domain string, raw []byte) string {
	d := hmac.New(sha256.New, w.completionKey)
	d.Write([]byte(domain))
	m := hmac.New(sha256.New, d.Sum(nil))
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil))
}
func managedVector(raw []byte) ([]byte, error) {
	if validateManagedEmbeddingResult(raw) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	var r struct {
		Data []struct {
			Embedding []json.Number `json:"embedding"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	out := make([]byte, 4096)
	for i, n := range r.Data[0].Embedding {
		v, e := n.Float64()
		if e != nil {
			return nil, e
		}
		binary.LittleEndian.PutUint32(out[i*4:], math.Float32bits(float32(v)))
	}
	return out, nil
}
func validManagedVector(raw []byte) bool {
	if len(raw) != 4096 {
		return false
	}
	for i := 0; i < len(raw); i += 4 {
		v := float64(math.Float32frombits(binary.LittleEndian.Uint32(raw[i:])))
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	return true
}

// One boot identity per actual SQL handle, even when existing DI constructors
// request the worker twice. A reopened handle always receives a fresh boot.
var managedBoots sync.Map

func (w *pilotManagedWorker) initCompletion(key []byte) error {
	if w.db.Dialector.Name() != "sqlite" {
		return ErrManagedWorkerUnavailable
	}
	w.completionKey = append([]byte(nil), key...)
	if err := w.db.AutoMigrate(&managedStoreMeta{}, &managedProducer{}, &managedCompletion{}); err != nil {
		return err
	}
	err := w.db.Transaction(func(tx *gorm.DB) error {
		var meta managedStoreMeta
		err := tx.First(&meta, 1).Error
		if err == gorm.ErrRecordNotFound {
			// Never silently give an existing managed store a new identity.
			var n int64
			for _, table := range []string{"managed_knowledge_registration", "managed_index_producers", "managed_index_completions"} {
				if e := tx.Table(table).Count(&n).Error; e != nil {
					return e
				}
				if n != 0 {
					return ErrManagedWorkerUnavailable
				}
			}
			id, e := managedRandom()
			if e != nil {
				return e
			}
			gen, e := managedRandom()
			if e != nil {
				return e
			}
			meta = managedStoreMeta{ID: 1, StorageID: id, StorageGeneration: gen}
			meta.MAC = w.seal("managed-store-v1", []byte(id+"\n"+gen))
			if e = tx.Create(&meta).Error; e != nil {
				return e
			}
		} else if err != nil {
			return err
		}
		if !hmac.Equal([]byte(meta.MAC), []byte(w.seal("managed-store-v1", []byte(meta.StorageID+"\n"+meta.StorageGeneration)))) {
			return ErrManagedWorkerUnavailable
		}
		w.storage = meta
		return nil
	})
	if err != nil {
		return err
	}
	sqlDB, err := w.db.DB()
	if err != nil {
		return err
	}
	boot, err := managedRandom()
	if err != nil {
		return err
	}
	actual, _ := managedBoots.LoadOrStore(sqlDB, boot)
	w.workerBootID = actual.(string)
	return nil
}
func (w *pilotManagedWorker) checkStorageTx(tx *gorm.DB, b managedcapability.IndexBinding) error {
	if tx == nil || tx.Dialector.Name() != "sqlite" || !managedcapability.ValidIndexBinding(b) {
		return ErrManagedWorkerUnavailable
	}
	var m managedStoreMeta
	if tx.First(&m, 1).Error != nil || m != w.storage || b.StorageID != m.StorageID || b.StorageGeneration != m.StorageGeneration || !hmac.Equal([]byte(m.MAC), []byte(w.seal("managed-store-v1", []byte(m.StorageID+"\n"+m.StorageGeneration)))) {
		return ErrManagedWorkerUnavailable
	}
	return nil
}

// Triggers run in the mutator's transaction, including native chunk writers.
// Virtual-table writes are additionally invalidated in sqlite repository helpers.
func (w *pilotManagedWorker) installCompletionGuards() error {
	for _, table := range []string{"chunks", "lite_embeddings"} {
		for _, op := range []string{"INSERT", "UPDATE", "DELETE"} {
			refs := []string{"NEW"}
			if op == "DELETE" {
				refs = []string{"OLD"}
			}
			if op == "UPDATE" {
				refs = []string{"OLD", "NEW"}
			}
			var stmts []string
			for _, ref := range refs {
				stmts = append(stmts, fmt.Sprintf("UPDATE managed_index_completions SET invalid=1, revision=revision+1 WHERE knowledge_id=%s.knowledge_id AND invalid=0;", ref))
			}
			sql := fmt.Sprintf("CREATE TRIGGER IF NOT EXISTS managed_invalidate_%s_%s AFTER %s ON %s BEGIN %s END", table, strings.ToLower(op), op, table, strings.Join(stmts, " "))
			if err := w.db.Exec(sql).Error; err != nil {
				return err
			}
		}
	}
	return nil
}
func (w *pilotManagedWorker) saveProducer(ctx context.Context, b managedcapability.Binding, snapshot []byte, input string, raw []byte, c managedcapability.ResultClaims) error {
	if !managedcapability.ValidIndexBinding(b.IndexBinding) || c.Binding != b || c.CallID == "" || c.AttemptID == "" || c.ProducerCredentialID == "" || c.Status != "SETTLED" || c.ContentSHA256 != managedSHA(raw) {
		return ErrManagedWorkerUnavailable
	}
	vector, err := managedVector(raw)
	if err != nil {
		return err
	}
	p := managedProducerFacts{Binding: b, CallID: c.CallID, AttemptID: c.AttemptID, ProducerCredentialID: c.ProducerCredentialID, SnapshotSHA256: managedSHA(snapshot), InputSHA256: managedSHA([]byte(input)), RawResultSHA256: managedSHA(raw), Float32SHA256: managedSHA(vector), Vector: vector}
	payload, err := json.Marshal(p)
	if err != nil {
		return err
	}
	row := managedProducer{WorkID: b.WorkID, Payload: string(payload), MAC: w.seal("managed-producer-v1", payload)}
	return w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := w.checkStorageTx(tx, b.IndexBinding); err != nil {
			return err
		}
		saved, err := w.lookup(ctx, tx, b.WorkID)
		if err != nil || saved != b {
			return ErrManagedWorkerUnavailable
		}
		if err = tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			return err
		}
		var old managedProducer
		if tx.First(&old, "work_id = ?", b.WorkID).Error != nil || old != row {
			return ErrManagedWorkerUnavailable
		}
		return nil
	})
}
func (w *pilotManagedWorker) producerTx(tx *gorm.DB, work string) (managedProducerFacts, error) {
	var row managedProducer
	var p managedProducerFacts
	if tx.First(&row, "work_id = ?", work).Error != nil || !hmac.Equal([]byte(row.MAC), []byte(w.seal("managed-producer-v1", []byte(row.Payload)))) || managedcapability.StrictJSON([]byte(row.Payload), &p) != nil || !validManagedVector(p.Vector) || p.Float32SHA256 != managedSHA(p.Vector) || p.Binding.WorkID != work {
		return p, ErrManagedWorkerUnavailable
	}
	return p, nil
}
func (w *pilotManagedWorker) referencesTx(ctx context.Context, tx *gorm.DB, p managedProducerFacts) (managedReferences, string, error) {
	var refs managedReferences
	fail := func() (managedReferences, string, error) { return refs, "", ErrManagedWorkerUnavailable }
	b := p.Binding
	if w.checkStorageTx(tx, b.IndexBinding) != nil {
		return fail()
	}
	// Exact bytes in an ordinary BLOB table do not establish a usable vec0
	// index. Inspect the actual schema through this same transaction handle.
	var schema string
	if tx.Raw("SELECT sql FROM sqlite_master WHERE type='table' AND name='vec_embeddings_1024'").Scan(&schema).Error != nil {
		return fail()
	}
	// Accept only the schema emitted by this SQLite repository. A different
	// vec0 type can expose identical bytes while refusing float32 queries;
	// another distance metric would silently change retrieval semantics.
	schema = strings.Join(strings.Fields(strings.ToLower(schema)), "")
	schema = strings.Replace(schema, "createvirtualtableifnotexists", "createvirtualtable", 1)
	if schema != "createvirtualtablevec_embeddings_1024usingvec0(embeddingfloat[1024]distance_metric=cosine)" {
		return fail()
	}
	saved, err := w.lookup(ctx, tx, b.WorkID)
	if err != nil || saved != b {
		return fail()
	}
	if tx.Where("id = ? AND tenant_id = ? AND knowledge_base_id = ? AND managed_work_id = ?", b.KnowledgeID, b.TenantID, b.KnowledgeBaseID, b.WorkID).First(&refs.Knowledge).Error != nil || refs.Knowledge.PendingSubtasksCount != 0 {
		return fail()
	}
	var kb types.KnowledgeBase
	if tx.Where("id = ? AND tenant_id = ?", b.KnowledgeBaseID, b.TenantID).First(&kb).Error != nil {
		return fail()
	}
	var chunks []types.Chunk
	if tx.Where("knowledge_id = ?", b.KnowledgeID).Find(&chunks).Error != nil || len(chunks) != 1 {
		return fail()
	}
	refs.Chunk = chunks[0]
	c := refs.Chunk
	if c.TenantID != b.TenantID || c.KnowledgeBaseID != b.KnowledgeBaseID || !c.IsEnabled || c.ChunkType != types.ChunkTypeText || c.ChunkIndex != 0 || managedSHA([]byte(c.Content)) != p.SnapshotSHA256 {
		return fail()
	}
	var rows []struct {
		ID              uint64
		SourceID        string
		SourceType      int
		ChunkID         string
		KnowledgeBaseID string
		Dimension       int
		IsEnabled       *bool
		Content         string
	}
	if tx.Table("lite_embeddings").Where("knowledge_id = ?", b.KnowledgeID).Find(&rows).Error != nil || len(rows) != 1 {
		return fail()
	}
	e := rows[0]
	if e.SourceID != c.ID || e.ChunkID != c.ID || e.SourceType != int(types.ChunkSourceType) || e.KnowledgeBaseID != b.KnowledgeBaseID || e.Dimension != 1024 || e.IsEnabled == nil || !*e.IsEnabled || e.Content != buildKnowledgeIndexContent(&refs.Knowledge, c.Content) || managedSHA([]byte(e.Content)) != p.InputSHA256 {
		return fail()
	}
	var vectors []struct{ Embedding []byte }
	if tx.Raw("SELECT embedding FROM vec_embeddings_1024 WHERE rowid = ?", e.ID).Scan(&vectors).Error != nil || len(vectors) != 1 || !validManagedVector(vectors[0].Embedding) || !bytes.Equal(vectors[0].Embedding, p.Vector) {
		return fail()
	}
	refs.EmbeddingID = e.ID
	refs.SourceID = e.SourceID
	refs.Vector = vectors[0].Embedding
	refs.Content = e.Content
	// Hash only immutable identity/content facts; ready flags are checked above.
	raw, _ := json.Marshal(struct {
		Binding     managedcapability.Binding
		ChunkID     string
		Revision    int
		SourceID    string
		EmbeddingID uint64
		InputSHA    string
		VectorSHA   string
		Title       string
		Source      string
	}{b, c.ID, c.ContentRevision, e.SourceID, e.ID, p.InputSHA256, p.Float32SHA256, refs.Knowledge.Title, refs.Knowledge.Source})
	return refs, managedSHA(raw), nil
}

// FinalizeManagedIndexTx performs no root DB, callback, journal, or model work.
func (w *pilotManagedWorker) FinalizeManagedIndexTx(ctx context.Context, tx *gorm.DB, work string) error {
	p, err := w.producerTx(tx, work)
	if err != nil {
		return err
	}
	refs, digest, err := w.referencesTx(ctx, tx, p)
	if err != nil {
		return err
	}
	var old managedCompletion
	err = tx.First(&old, "work_id = ?", work).Error
	if err == nil {
		_, _, err = w.ReadCompletedIndexTx(ctx, tx, work, p.Binding.IndexRevision, "")
		return err
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}
	if refs.Knowledge.ParseStatus != types.ParseStatusProcessing {
		return ErrManagedWorkerUnavailable
	}
	facts := managedCompletionFacts{Producer: p, ReferenceDigest: digest, ChunkID: refs.Chunk.ID, SourceID: refs.SourceID, EmbeddingID: refs.EmbeddingID}
	raw, err := json.Marshal(facts)
	if err != nil {
		return err
	}
	row := managedCompletion{WorkID: work, KnowledgeID: p.Binding.KnowledgeID, Revision: p.Binding.IndexRevision, Payload: string(raw), MAC: w.seal("managed-completion-v1", raw)}
	if err = tx.Create(&row).Error; err != nil {
		return err
	}
	result := tx.Model(&types.Knowledge{}).Where("id = ? AND tenant_id = ? AND managed_work_id = ? AND parse_status = ? AND pending_subtasks_count = 0", p.Binding.KnowledgeID, p.Binding.TenantID, work, types.ParseStatusProcessing).Updates(map[string]any{"parse_status": types.ParseStatusCompleted, "enable_status": "enabled"})
	if result.Error != nil || result.RowsAffected != 1 {
		return ErrManagedWorkerUnavailable
	}
	return nil
}
func (w *pilotManagedWorker) ReadCompletedIndexTx(ctx context.Context, tx *gorm.DB, work string, revision int64, expectedDigest string) (managedCompletion, managedReferences, error) {
	var row managedCompletion
	var refs managedReferences
	var facts managedCompletionFacts
	if tx.First(&row, "work_id = ?", work).Error != nil || row.Invalid || row.Revision != revision || !hmac.Equal([]byte(row.MAC), []byte(w.seal("managed-completion-v1", []byte(row.Payload)))) || managedcapability.StrictJSON([]byte(row.Payload), &facts) != nil || facts.Producer.Binding.WorkID != work || facts.Producer.Binding.IndexRevision != revision || row.KnowledgeID != facts.Producer.Binding.KnowledgeID {
		return row, refs, ErrManagedWorkerUnavailable
	}
	if expectedDigest != "" && managedSHA([]byte(row.Payload)) != expectedDigest {
		return row, refs, ErrManagedWorkerUnavailable
	}
	refs, digest, err := w.referencesTx(ctx, tx, facts.Producer)
	if err != nil || digest != facts.ReferenceDigest || refs.Chunk.ID != facts.ChunkID || refs.SourceID != facts.SourceID || refs.EmbeddingID != facts.EmbeddingID || refs.Knowledge.ParseStatus != types.ParseStatusCompleted || refs.Knowledge.EnableStatus != "enabled" {
		return row, refs, ErrManagedWorkerUnavailable
	}
	return row, refs, nil
}
func (w *pilotManagedWorker) RevalidateCompletionTx(ctx context.Context, tx *gorm.DB, c managedCompletion) error {
	_, _, err := w.ReadCompletedIndexTx(ctx, tx, c.WorkID, c.Revision, managedSHA([]byte(c.Payload)))
	return err
}
func (w *pilotManagedWorker) ReadManagedCandidatesTx(ctx context.Context, tx *gorm.DB, c managedCompletion, query []byte) (*types.SearchResult, error) {
	_, refs, err := w.ReadCompletedIndexTx(ctx, tx, c.WorkID, c.Revision, managedSHA([]byte(c.Payload)))
	if err != nil || !validManagedVector(query) {
		return nil, ErrManagedWorkerUnavailable
	}
	var found []struct {
		Rowid    uint64
		Distance float64
	}
	if tx.Raw("SELECT rowid,distance FROM vec_embeddings_1024 WHERE embedding MATCH ? AND k=1 AND rowid IN (?)", query, refs.EmbeddingID).Scan(&found).Error != nil || len(found) != 1 || found[0].Rowid != refs.EmbeddingID || math.IsNaN(found[0].Distance) || math.IsInf(found[0].Distance, 0) {
		return nil, ErrManagedWorkerUnavailable
	}
	return &types.SearchResult{ID: refs.Chunk.ID, Content: refs.Chunk.Content, KnowledgeID: refs.Knowledge.ID, KnowledgeTitle: refs.Knowledge.Title, KnowledgeFilename: refs.Knowledge.FileName, KnowledgeSource: refs.Knowledge.Source, ChunkType: refs.Chunk.ChunkType, Score: 1 - found[0].Distance, MatchType: types.MatchTypeEmbedding}, nil
}
func (s *knowledgeBaseService) CompleteManagedIndex(ctx context.Context, work string) error {
	w := s.managedWorker
	if w == nil {
		return ErrManagedWorkerUnavailable
	}
	if err := w.installCompletionGuards(); err != nil {
		return err
	}
	return w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error { return w.FinalizeManagedIndexTx(ctx, tx, work) })
}

// Response payload order is fixed by this struct; MAC excludes only MAC itself.
type ManagedCompletionReply struct {
	Version         string                         `json:"version"`
	Scope           managedcapability.CompletedUse `json:"scope"`
	Nonce           string                         `json:"nonce"`
	ReferenceDigest string                         `json:"reference_digest"`
	State           string                         `json:"state"`
	IssuedAt        int64                          `json:"issued_at"`
	ExpiresAt       int64                          `json:"expires_at"`
	MAC             string                         `json:"mac,omitempty"`
}

func (w *pilotManagedWorker) completedStatus(ctx context.Context, tenant uint64, kb, method, path string, body []byte, token, proof string) (*ManagedStatus, error) {
	c, err := w.verifier.DecodeCompletedUse(token)
	if err != nil || c.TenantID != tenant || c.KnowledgeBaseID != kb || c.WorkerBootID != w.workerBootID || c.StorageID != w.storage.StorageID || c.StorageGeneration != w.storage.StorageGeneration {
		return nil, ErrManagedWorkerUnavailable
	}
	request, err := w.verifier.VerifyRequest(proof, method, path, body, c.WorkID, c.ActorID, c.AccountID)
	if err != nil || w.acceptProof(ctx, method, path, body, proof, c.WorkID, c.ActorID, c.AccountID) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	if w.host.CompletedCheck(ctx, c) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	var row managedCompletion
	var facts managedCompletionFacts
	err = w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var e error
		row, _, e = w.ReadCompletedIndexTx(ctx, tx, c.WorkID, c.IndexRevision, c.CompletionDigest)
		if e != nil {
			return e
		}
		if managedcapability.StrictJSON([]byte(row.Payload), &facts) != nil {
			return ErrManagedWorkerUnavailable
		}
		b := facts.Producer.Binding
		if b.NamespaceID != c.NamespaceID || b.TenantID != c.TenantID || b.ActorID != c.ActorID || b.AccountID != c.AccountID || b.KnowledgeBaseID != c.KnowledgeBaseID || b.KnowledgeID != c.KnowledgeID {
			return ErrManagedWorkerUnavailable
		}
		return nil
	})
	if err != nil || w.host.CompletedCheck(ctx, c) != nil || !w.verifier.ValidCompletedUse(c) {
		return nil, ErrManagedWorkerUnavailable
	}
	now := time.Now().Unix()
	reply := ManagedCompletionReply{Version: "completed-index-response-v1", Scope: c, Nonce: request.Nonce, ReferenceDigest: facts.ReferenceDigest, State: "ready", IssuedAt: now, ExpiresAt: min(now+30, c.ExpiresAt)}
	raw, _ := json.Marshal(reply)
	reply.MAC = w.host.CompletionResponseMAC(raw)
	return &ManagedStatus{ID: c.KnowledgeID, ParseStatus: types.ParseStatusCompleted, Completion: &reply}, nil
}

type ManagedStorageReply struct {
	Version           string                           `json:"version"`
	Scope             managedcapability.StorageRequest `json:"scope"`
	Nonce             string                           `json:"nonce"`
	StorageID         string                           `json:"storage_id"`
	StorageGeneration string                           `json:"storage_generation"`
	WorkerBootID      string                           `json:"worker_boot_id"`
	Driver            string                           `json:"driver"`
	IssuedAt          int64                            `json:"issued_at"`
	ExpiresAt         int64                            `json:"expires_at"`
	MAC               string                           `json:"mac,omitempty"`
}

func (w *pilotManagedWorker) storageStatus(ctx context.Context, tenant uint64, kb, method, path string, body []byte, token, proof string) (*ManagedStatus, error) {
	c, err := w.verifier.DecodeStorageRequest(token)
	if err != nil || c.TenantID != tenant || c.KnowledgeBaseID != kb {
		return nil, ErrManagedWorkerUnavailable
	}
	r, err := w.verifier.VerifyRequest(proof, method, path, body, c.WorkID, c.ActorID, c.AccountID)
	if err != nil || w.acceptProof(ctx, method, path, body, proof, c.WorkID, c.ActorID, c.AccountID) != nil || w.host.StorageCheck(ctx, c) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	var m managedStoreMeta
	if w.db.WithContext(ctx).First(&m, 1).Error != nil || m != w.storage {
		return nil, ErrManagedWorkerUnavailable
	}
	if _, err = w.verifier.DecodeStorageRequest(token); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	reply := ManagedStorageReply{Version: "managed-storage-response-v1", Scope: c, Nonce: r.Nonce, StorageID: m.StorageID, StorageGeneration: m.StorageGeneration, WorkerBootID: w.workerBootID, Driver: "sqlite", IssuedAt: now, ExpiresAt: min(now+30, c.ExpiresAt)}
	raw, _ := json.Marshal(reply)
	reply.MAC = w.host.CompletionResponseMAC(raw)
	return &ManagedStatus{Storage: &reply}, nil
}

type ManagedDiscoveryReply struct {
	Version              string                               `json:"version"`
	Scope                managedcapability.CompletionDiscover `json:"scope"`
	Nonce                string                               `json:"nonce"`
	CompletionDigest     string                               `json:"completion_digest"`
	ReferenceDigest      string                               `json:"reference_digest"`
	IndexRevision        int64                                `json:"index_revision"`
	CallID               string                               `json:"call_id"`
	AttemptID            string                               `json:"attempt_id"`
	ProducerCredentialID string                               `json:"producer_credential_id"`
	InputSHA256          string                               `json:"input_sha256"`
	RawResultSHA256      string                               `json:"raw_result_sha256"`
	Float32SHA256        string                               `json:"float32_sha256"`
	State                string                               `json:"state"`
	IssuedAt             int64                                `json:"issued_at"`
	ExpiresAt            int64                                `json:"expires_at"`
	MAC                  string                               `json:"mac,omitempty"`
}

func (w *pilotManagedWorker) discoveryStatus(ctx context.Context, tenant uint64, kb, method, path string, body []byte, token, proof string) (*ManagedStatus, error) {
	c, err := w.verifier.DecodeCompletionDiscover(token)
	if err != nil || c.Binding.TenantID != tenant || c.Binding.KnowledgeBaseID != kb || c.WorkerBootID != w.workerBootID {
		return nil, ErrManagedWorkerUnavailable
	}
	b := c.Binding
	r, err := w.verifier.VerifyRequest(proof, method, path, body, b.WorkID, b.ActorID, b.AccountID)
	if err != nil || w.acceptProof(ctx, method, path, body, proof, b.WorkID, b.ActorID, b.AccountID) != nil || w.host.DiscoverCheck(ctx, c) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	var row managedCompletion
	var facts managedCompletionFacts
	err = w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var e error
		row, _, e = w.ReadCompletedIndexTx(ctx, tx, b.WorkID, b.IndexRevision, "")
		if e != nil {
			return e
		}
		if managedcapability.StrictJSON([]byte(row.Payload), &facts) != nil || facts.Producer.Binding != b || facts.Producer.SnapshotSHA256 != c.SnapshotSHA256 {
			return ErrManagedWorkerUnavailable
		}
		return nil
	})
	if err != nil || w.host.DiscoverCheck(ctx, c) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	if _, err = w.verifier.DecodeCompletionDiscover(token); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	p := facts.Producer
	reply := ManagedDiscoveryReply{Version: "completed-index-discovery-response-v1", Scope: c, Nonce: r.Nonce, CompletionDigest: managedSHA([]byte(row.Payload)), ReferenceDigest: facts.ReferenceDigest, IndexRevision: row.Revision, CallID: p.CallID, AttemptID: p.AttemptID, ProducerCredentialID: p.ProducerCredentialID, InputSHA256: p.InputSHA256, RawResultSHA256: p.RawResultSHA256, Float32SHA256: p.Float32SHA256, State: "ready", IssuedAt: now, ExpiresAt: min(now+30, c.ExpiresAt)}
	raw, _ := json.Marshal(reply)
	reply.MAC = w.host.CompletionResponseMAC(raw)
	return &ManagedStatus{ID: b.KnowledgeID, ParseStatus: types.ParseStatusCompleted, Discovery: &reply}, nil
}
