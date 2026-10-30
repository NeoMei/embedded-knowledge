package service

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type managedRegistration struct {
	WorkID      string `gorm:"primaryKey;size:200"`
	KnowledgeID string `gorm:"uniqueIndex;size:36;not null"`
	GrantID     string `gorm:"uniqueIndex;size:200;not null"`
	Ciphertext  string `gorm:"type:text;not null"`
}
type managedRegistrationMeta struct {
	ID       int    `gorm:"primaryKey"`
	Verifier string `gorm:"size:64;not null"`
}
type managedRequestNonce struct {
	Hash      string `gorm:"primaryKey;size:64"`
	ExpiresAt int64
}

func (managedRequestNonce) TableName() string { return "managed_knowledge_request_nonces" }

func (managedRegistrationMeta) TableName() string { return "managed_knowledge_registration_meta" }

func (managedRegistration) TableName() string { return "managed_knowledge_registration" }

type pilotManagedWorker struct {
	db            *gorm.DB
	verifier      *managedcapability.Verifier
	host          *managedcapability.HostAuthority
	journal       *managedjournal.Journal
	aead          cipher.AEAD
	completionKey []byte
	storage       managedStoreMeta
	workerBootID  string
}

// newPilotManagedWorker is only constructed with server-controlled dependencies.
// The current restricted pilot supports one UTF-8 TXT batch up to 300 bytes.
// pilotWorkerFromEnvironment is an explicit, disabled-by-default local test
// configuration. Do not enable against production until review and recovery.
func pilotWorkerFromEnvironment(db *gorm.DB) (*pilotManagedWorker, error) {
	if os.Getenv("WEKNORA_MANAGED_KNOWLEDGE_PILOT") != "1" {
		return nil, nil
	}
	pub, err := base64.StdEncoding.DecodeString(os.Getenv("WEKNORA_MANAGED_KNOWLEDGE_PUBLIC_KEY"))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, ErrManagedWorkerUnavailable
	}
	verifier, err := managedcapability.NewVerifier("superwagie-knowledge-v1", "weknora", map[string]ed25519.PublicKey{"host-v1": pub}, time.Hour, time.Now)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	readKey := func(name string) ([]byte, error) {
		return readManagedKeyFile(os.Getenv(name))
	}
	callbackKey, err := readKey("WEKNORA_MANAGED_CALLBACK_KEY_FILE")
	if err != nil {
		return nil, err
	}
	host, err := managedcapability.NewHostAuthority(os.Getenv("WEKNORA_MANAGED_KNOWLEDGE_AUTH_URL"), verifier, &http.Client{}, callbackKey)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	journalKey, err := readKey("WEKNORA_MANAGED_JOURNAL_KEY_FILE")
	if err != nil {
		return nil, err
	}
	callKey, err := readKey("WEKNORA_MANAGED_CALL_KEY_FILE")
	if err != nil {
		return nil, err
	}
	bindingKey, err := readKey("WEKNORA_MANAGED_BINDING_KEY_FILE")
	if err != nil {
		return nil, err
	}
	if hmac.Equal(journalKey, callKey) || hmac.Equal(journalKey, bindingKey) || hmac.Equal(callKey, bindingKey) {
		return nil, ErrManagedWorkerUnavailable
	}
	journal, err := managedjournal.Open(db, journalKey, callKey, time.Hour)
	if err != nil {
		return nil, err
	}
	return newPilotManagedWorker(db, verifier, host, journal, bindingKey)
}

func newPilotManagedWorker(db *gorm.DB, verifier *managedcapability.Verifier, host *managedcapability.HostAuthority, journal *managedjournal.Journal, key []byte) (*pilotManagedWorker, error) {
	if db == nil || verifier == nil || host == nil || journal == nil || len(key) != 32 {
		return nil, ErrManagedWorkerUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	db = db.Session(&gorm.Session{Logger: logger.Discard})
	if err = db.AutoMigrate(&managedRegistration{}, &managedRegistrationMeta{}, &managedRequestNonce{}); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("managed-registration-key-verifier-v1"))
	verifierHash := hex.EncodeToString(mac.Sum(nil))
	err = db.Transaction(func(tx *gorm.DB) error {
		candidate := managedRegistrationMeta{ID: 1, Verifier: verifierHash}
		inserted := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&candidate)
		if inserted.Error != nil {
			return inserted.Error
		}
		var saved managedRegistrationMeta
		if err := tx.First(&saved, 1).Error; err != nil {
			return err
		}
		if !hmac.Equal([]byte(saved.Verifier), []byte(verifierHash)) {
			return ErrManagedWorkerUnavailable
		}
		if inserted.RowsAffected == 1 {
			var count int64
			if err := tx.Model(&managedRegistration{}).Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return ErrManagedWorkerUnavailable
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	w := &pilotManagedWorker{db: db, verifier: verifier, host: host, journal: journal, aead: aead}
	if err := w.initCompletion(key); err != nil {
		return nil, err
	}
	return w, nil
}

// Proofs are consumed atomically and retained as replay tombstones. Cleanup
// must not be introduced without a trusted clock and rollback-safe retention.
func (w *pilotManagedWorker) acceptProof(ctx context.Context, method, path string, body []byte, proof, work, actor, account string) error {
	_, err := w.acceptProofClaims(ctx, method, path, body, proof, work, actor, account)
	return err
}

func (w *pilotManagedWorker) acceptProofClaims(ctx context.Context, method, path string, body []byte, proof, work, actor, account string) (managedcapability.RequestClaims, error) {
	if w == nil {
		return managedcapability.RequestClaims{}, ErrManagedWorkerUnavailable
	}
	claims, err := w.verifier.VerifyRequest(proof, method, path, body, work, actor, account)
	if err != nil {
		return managedcapability.RequestClaims{}, ErrManagedWorkerUnavailable
	}
	sum := sha256.Sum256([]byte(claims.Nonce))
	row := managedRequestNonce{Hash: hex.EncodeToString(sum[:]), ExpiresAt: claims.ExpiresAt}
	result := w.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if result.Error != nil || result.RowsAffected != 1 {
		return managedcapability.RequestClaims{}, ErrManagedWorkerUnavailable
	}
	return claims, nil
}
func (w *pilotManagedWorker) Register(ctx context.Context, tenant uint64, kb, path, token string) (managedcapability.Binding, error) {
	claims, err := w.verifier.DecodeVerified(token)
	if err != nil {
		return managedcapability.Binding{}, ErrManagedWorkerUnavailable
	}
	b := claims.Binding
	if !managedcapability.ValidIndexBinding(b.IndexBinding) || w.checkStorageTx(w.db, b.IndexBinding) != nil || b.TenantID != tenant || b.KnowledgeBaseID != kb || !strings.EqualFold(filepath.Ext(path), ".txt") || w.host.Check(ctx, b) != nil {
		return managedcapability.Binding{}, ErrManagedWorkerUnavailable
	}
	snapshot, err := w.host.Snapshot(ctx, b)
	if err != nil || !pilotDocumentText(snapshot) {
		return managedcapability.Binding{}, ErrManagedWorkerUnavailable
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return managedcapability.Binding{}, err
	}
	nonce := make([]byte, w.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return managedcapability.Binding{}, err
	}
	encrypted := w.aead.Seal(nonce, nonce, raw, []byte(b.WorkID))
	row := managedRegistration{WorkID: b.WorkID, KnowledgeID: b.KnowledgeID, GrantID: b.GrantID, Ciphertext: base64.RawStdEncoding.EncodeToString(encrypted)}
	err = w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			return err
		}
		existing, err := w.lookup(ctx, tx, b.WorkID)
		if err != nil || existing != b {
			return ErrManagedWorkerUnavailable
		}
		return nil
	})
	if err != nil {
		return managedcapability.Binding{}, err
	}
	return b, nil
}
func (w *pilotManagedWorker) lookup(ctx context.Context, db *gorm.DB, workID string) (managedcapability.Binding, error) {
	var row managedRegistration
	var b managedcapability.Binding
	if err := db.WithContext(ctx).First(&row, "work_id = ?", workID).Error; err != nil {
		return b, err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(row.Ciphertext)
	if err != nil || len(ciphertext) < w.aead.NonceSize()+w.aead.Overhead() {
		return b, ErrManagedWorkerUnavailable
	}
	raw, err := w.aead.Open(nil, ciphertext[:w.aead.NonceSize()], ciphertext[w.aead.NonceSize():], []byte(workID))
	if err != nil || json.Unmarshal(raw, &b) != nil || b.WorkID != workID || b.KnowledgeID != row.KnowledgeID || b.GrantID != row.GrantID || b.EmbeddingModel != managedcapability.EmbeddingModel || b.EmbeddingSpace != managedcapability.EmbeddingSpace {
		return managedcapability.Binding{}, ErrManagedWorkerUnavailable
	}
	return b, nil
}
func validateManagedEmbeddingResult(raw []byte) error {
	var shape any
	if managedcapability.StrictJSON(raw, &shape) != nil {
		return ErrManagedWorkerUnavailable
	}
	var response struct {
		Data []struct {
			Index     *int  `json:"index"`
			Embedding []any `json:"embedding"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&response) != nil || len(response.Data) != 1 || response.Data[0].Index == nil || *response.Data[0].Index != 0 || len(response.Data[0].Embedding) != managedcapability.EmbeddingDimensions {
		return ErrManagedWorkerUnavailable
	}
	for _, value := range response.Data[0].Embedding {
		number, ok := value.(json.Number)
		if !ok {
			return ErrManagedWorkerUnavailable
		}
		n, err := number.Float64()
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || math.Abs(n) > math.MaxFloat32 {
			return ErrManagedWorkerUnavailable
		}
	}
	return nil
}
func pilotText(data []byte) bool {
	if len(data) == 0 || len(data) > 300 || !utf8.Valid(data) || string(data) != strings.TrimSpace(string(data)) {
		return false
	}
	for _, r := range string(data) {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return !strings.Contains(string(data), "#")
}

// Documents keep their original snapshot and chunk bytes. Only the existing
// embedding path trims edge whitespace; the query validator remains strict.
func pilotDocumentText(data []byte) bool {
	if len(data) == 0 || len(data) > 300 || !utf8.Valid(data) || strings.TrimSpace(string(data)) == "" {
		return false
	}
	for _, r := range string(data) {
		if r == '#' || !(r == '\n' || (r >= 0x20 && r <= 0x7e) || (r >= 0x3400 && r <= 0x9fff) || (r >= 0x3000 && r <= 0x303f) || (r >= 0xff01 && r <= 0xff5e)) {
			return false
		}
	}
	return true
}
func (w *pilotManagedWorker) Prepare(ctx context.Context, p types.DocumentProcessPayload) (*managedWorkerAdmission, error) {
	b, err := w.lookup(ctx, w.db, p.ManagedWorkID)
	if err != nil || b.TenantID != p.TenantID || b.KnowledgeBaseID != p.KnowledgeBaseID || b.KnowledgeID != p.KnowledgeID || !strings.EqualFold(filepath.Ext(p.FileName), ".txt") || w.host.Check(ctx, b) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	snapshot, err := w.host.Snapshot(ctx, b)
	if err != nil || !pilotDocumentText(snapshot) {
		return nil, ErrManagedWorkerUnavailable
	}
	expected := strings.TrimSpace(p.FileName) + "\n" + strings.TrimSpace(string(snapshot))
	dispatch := func(callCtx context.Context, model, url string, body []byte) ([]byte, error) {
		start, ok := api.ManagedBatchStart(callCtx)
		if !ok || start != 0 {
			return nil, fmt.Errorf("managed pilot batch position unavailable: %w", ErrManagedWorkerUnavailable)
		}
		if model != b.EmbeddingModel {
			return nil, fmt.Errorf("managed pilot model mismatch: %w", ErrManagedWorkerUnavailable)
		}
		if w.host.Check(callCtx, b) != nil {
			return nil, fmt.Errorf("managed pilot authorization unavailable: %w", ErrManagedWorkerUnavailable)
		}
		var req struct {
			Model          string   `json:"model"`
			Input          []string `json:"input"`
			EncodingFormat string   `json:"encoding_format,omitempty"`
			Dimensions     int      `json:"dimensions,omitempty"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&req) != nil {
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(body, &fields)
			extra := "other"
			for _, key := range []string{"input_type", "task", "task_type", "taskType", "truncate", "truncate_prompt_tokens", "user", "parameters", "encoding_format", "dimensions"} {
				if _, exists := fields[key]; exists && key != "encoding_format" && key != "dimensions" {
					extra = key
					break
				}
			}
			return nil, fmt.Errorf("managed pilot request shape invalid (%s): %w", extra, ErrManagedWorkerUnavailable)
		}
		if req.Model != model || (req.Dimensions != 0 && req.Dimensions != managedcapability.EmbeddingDimensions) {
			return nil, fmt.Errorf("managed pilot request model mismatch: %w", ErrManagedWorkerUnavailable)
		}
		if len(req.Input) != 1 {
			return nil, fmt.Errorf("managed pilot requires one input: %w", ErrManagedWorkerUnavailable)
		}
		if req.Input[0] != expected {
			return nil, fmt.Errorf("managed pilot chunk mismatch: %w", ErrManagedWorkerUnavailable)
		}
		hash := sha256.Sum256(body)
		plan := hex.EncodeToString(hash[:])
		scope := managedjournal.Scope{TenantID: strconv.FormatUint(b.TenantID, 10), ActorID: b.ActorID, AccountID: b.AccountID, TaskID: b.TaskID, LogicalID: b.WorkID, Operation: "embedding", Model: model, PlanDigest: plan, Batch: start}
		result, err := w.journal.Execute(callCtx, scope, body, func(c context.Context, callID string) ([]byte, error) {
			if w.host.Check(c, b) != nil {
				return nil, managedjournal.ErrDefinitelyNotSent
			}
			return w.host.Dispatch(c, b, callID, model, body)
		})
		if errors.Is(err, managedjournal.ErrUnresolved) {
			result, err = w.journal.Recover(callCtx, scope, body, func(c context.Context, callID string) ([]byte, error) {
				if w.host.Check(c, b) != nil {
					return nil, ErrManagedWorkerUnavailable
				}
				return w.host.Result(c, b, callID, model, "embedding", "embeddings.create")
			})
		}
		if err != nil {
			return nil, err
		}
		info, err := w.journal.Inspect(callCtx, scope, body)
		if err != nil || info.Status != "COMPLETED" {
			return nil, ErrManagedWorkerUnavailable
		}
		confirmed, receipt, err := w.host.ResultWithEvidence(callCtx, b, info.CallID, model, "embedding", "embeddings.create")
		if err != nil || !hmac.Equal(result, confirmed) || w.host.Check(callCtx, b) != nil {
			return nil, ErrManagedWorkerUnavailable
		}
		if err := validateManagedEmbeddingResult(confirmed); err != nil {
			return nil, err
		}
		if err := w.saveProducer(callCtx, b, snapshot, expected, confirmed, receipt); err != nil {
			return nil, err
		}
		return confirmed, nil
	}
	return &managedWorkerAdmission{Context: api.WithManagedJSON(ctx, dispatch), Snapshot: snapshot}, nil
}
