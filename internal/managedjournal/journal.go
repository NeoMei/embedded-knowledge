// Package managedjournal provides a fail-closed durable ledger for individual
// managed model wire requests. It is not wired to provider transports: callers
// must first establish a trusted actor, payer, task and logical operation ID.
package managedjournal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

var (
	ErrInvalid     = errors.New("managed journal: invalid request scope")
	ErrConflict    = errors.New("managed journal: request ownership or input changed")
	ErrUnresolved  = errors.New("managed journal: request outcome unresolved")
	ErrExpired     = errors.New("managed journal: retained result expired")
	ErrLegacy      = errors.New("managed journal: legacy plaintext requires operator migration")
	ErrKeyMismatch = errors.New("managed journal: key does not match database")
	ErrCorrupt     = errors.New("managed journal: expired record failed authentication")
	// Only a trusted sender may return this when it can prove no upstream IO
	// occurred. Ambiguous transport failures must never use this marker.
	ErrDefinitelyNotSent = errors.New("managed journal: request definitely not sent")
)
var identity = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,200}$`)

const maxInput = 8 << 20
const maxResult = 16 << 20

// LogicalID must be a durable, unique ID for one user's logical action, not a
// content-derived cache key. The orchestrator must persist it before batching.
// Batch indexes must be stable under retry and refer to the exact wire batch.
type Scope struct {
	TenantID   string
	ActorID    string
	AccountID  string
	TaskID     string
	LogicalID  string
	Operation  string
	Model      string
	PlanDigest string
	Batch      int
}
type record struct {
	Key          string `gorm:"column:request_key;primaryKey;size:64"`
	CallID       string `gorm:"size:64;uniqueIndex;not null"`
	TenantID     string `gorm:"size:200;not null"`
	ActorID      string `gorm:"size:200;not null"`
	AccountID    string `gorm:"size:200;not null"`
	TaskID       string `gorm:"size:200;not null"`
	LogicalID    string `gorm:"size:200;not null"`
	Operation    string `gorm:"size:32;not null"`
	Model        string `gorm:"size:200;not null"`
	Batch        int    `gorm:"not null"`
	InputDigest  string `gorm:"size:64;not null"`
	BindingMAC   string `gorm:"size:64"`
	StateMAC     string `gorm:"size:64"`
	Status       string `gorm:"size:16;not null"`
	Result       []byte
	ResultHash   string `gorm:"size:64"`
	ExpiresAt    int64  `gorm:"index"`
	ResultDigest string `gorm:"size:64"`
}

func (record) TableName() string { return "managed_model_requests" }

type logicalOwner struct {
	OwnerKey   string `gorm:"primaryKey;size:64"`
	LogicalID  string `gorm:"size:200;not null"`
	TenantID   string `gorm:"size:200;not null"`
	ActorID    string `gorm:"size:200;not null"`
	AccountID  string `gorm:"size:200;not null"`
	TaskID     string `gorm:"size:200;not null"`
	BindingMAC string `gorm:"size:64"`
}

func (logicalOwner) TableName() string { return "managed_model_request_owners" }

type logicalOperation struct {
	Key        string `gorm:"column:operation_key;primaryKey;size:64"`
	Model      string `gorm:"size:200;not null"`
	PlanDigest string `gorm:"size:64;not null"`
	BindingMAC string `gorm:"size:64"`
}

func (logicalOperation) TableName() string { return "managed_model_request_operations" }

type journalMeta struct {
	ID              int    `gorm:"primaryKey"`
	Version         int    `gorm:"not null"`
	Verifier        string `gorm:"size:64;not null"`
	CallKeyVerifier string `gorm:"size:64"`
	CursorExpiry    int64
	CursorRevision  int64
	CursorKey       string `gorm:"size:64"`
	CursorMAC       string `gorm:"size:64"`
}

func (journalMeta) TableName() string { return "managed_model_journal_meta" }

type Journal struct {
	db        *gorm.DB
	macKey    []byte
	callKey   []byte
	aead      cipher.AEAD
	retention time.Duration
	now       func() time.Time
}

// Open prepares the isolated journal table; production wiring must coordinate
// schema deployment before enabling managed models.
func Open(db *gorm.DB, key, callKey []byte, retention time.Duration) (*Journal, error) {
	if db == nil || len(key) != 32 || len(callKey) != 32 || hmac.Equal(key, callKey) || retention <= 0 || retention > 30*24*time.Hour {
		return nil, ErrInvalid
	}
	// The key is supplied by the caller, never persisted. A silent logger also
	// ensures SQL error paths cannot print payloads, ciphertext, or arguments.
	db = db.Session(&gorm.Session{Logger: logger.Discard})
	if err := db.AutoMigrate(&logicalOwner{}, &logicalOperation{}, &record{}, &journalMeta{}); err != nil {
		return nil, err
	}
	derive := func(label string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(label))
		return h.Sum(nil)
	}
	verifier := hex.EncodeToString(derive("managed-journal:database-verifier:v1"))
	journal := &Journal{db: db, macKey: derive("managed-journal:input:v1"), callKey: append([]byte(nil), callKey...), retention: retention, now: time.Now}
	callVerifier := journal.callMAC("managed-journal:call-key-verifier:v1", nil)
	if err := db.Transaction(func(tx *gorm.DB) error {
		candidate := journalMeta{ID: 1, Version: 1, Verifier: verifier, CallKeyVerifier: callVerifier}
		candidate.CursorMAC = journal.cursorMAC(candidate)
		inserted := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&candidate)
		if inserted.Error != nil {
			return inserted.Error
		}
		var saved journalMeta
		if err := tx.First(&saved, 1).Error; err != nil {
			return err
		}
		if saved.Version != 1 || !hmac.Equal([]byte(saved.Verifier), []byte(verifier)) {
			return ErrKeyMismatch
		}
		if !equalMAC(saved.CallKeyVerifier, callVerifier) {
			return ErrKeyMismatch
		}
		if !equalMAC(saved.CursorMAC, journal.cursorMAC(saved)) {
			return ErrLegacy
		}
		if inserted.RowsAffected == 1 {
			for _, table := range []any{&record{}, &logicalOwner{}, &logicalOperation{}} {
				var count int64
				if err := tx.Model(table).Count(&count).Error; err != nil {
					return err
				}
				if count != 0 {
					return ErrLegacy
				}
			}
		}
		for _, item := range []struct {
			table     any
			condition string
		}{
			{&record{}, "binding_mac IS NULL OR binding_mac = '' OR state_mac IS NULL OR state_mac = '' OR (result_digest IS NOT NULL AND result_digest <> '')"},
			{&logicalOwner{}, "binding_mac IS NULL OR binding_mac = ''"},
			{&logicalOperation{}, "binding_mac IS NULL OR binding_mac = ''"},
		} {
			var count int64
			if err := tx.Model(item.table).Where(item.condition).Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return ErrLegacy
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derive("managed-journal:result:v1"))
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	journal.aead = aead
	return journal, nil
}
func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func (j *Journal) callMAC(label string, value []byte) string {
	h := hmac.New(sha256.New, j.callKey)
	_, _ = h.Write([]byte(label))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(value)
	return hex.EncodeToString(h.Sum(nil))
}
func (j *Journal) mac(label string, value []byte) string {
	h := hmac.New(sha256.New, j.macKey)
	_, _ = h.Write([]byte(label))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(value)
	return hex.EncodeToString(h.Sum(nil))
}
func (j *Journal) objectMAC(label string, value any) string {
	b, _ := json.Marshal(value)
	return j.mac(label, b)
}
func (j *Journal) ownerMAC(o logicalOwner) string {
	return j.objectMAC("owner-v1", []any{o.OwnerKey, o.LogicalID, o.TenantID, o.ActorID, o.AccountID, o.TaskID})
}
func (j *Journal) operationMAC(o logicalOperation) string {
	return j.objectMAC("operation-v1", []any{o.Key, o.Model, o.PlanDigest})
}
func (j *Journal) recordMAC(r record, operation logicalOperation) string {
	return j.objectMAC("request-v1", []any{r.Key, r.CallID, r.TenantID, r.ActorID, r.AccountID, r.TaskID, r.LogicalID, r.Operation, r.Model, r.Batch, r.InputDigest, operation.Key, operation.PlanDigest})
}
func (j *Journal) stateMAC(r record) string {
	return j.objectMAC("state-v1", []any{r.Key, r.BindingMAC, r.Status, r.ExpiresAt, r.ResultHash})
}
func (j *Journal) cursorMAC(m journalMeta) string {
	return j.objectMAC("retention-cursor-v1", []any{m.ID, m.Version, m.Verifier, m.CallKeyVerifier, m.CursorExpiry, m.CursorKey, m.CursorRevision})
}
func equalMAC(a, b string) bool { return len(a) == 64 && hmac.Equal([]byte(a), []byte(b)) }
func (j *Journal) validState(r record) bool {
	if !equalMAC(r.StateMAC, j.stateMAC(r)) {
		return false
	}
	switch r.Status {
	case "PREPARED", "DISPATCHED", "NOT_SENT":
		return r.ExpiresAt == 0 && len(r.Result) == 0 && r.ResultHash == ""
	case "EXPIRED":
		return r.ExpiresAt > 0 && len(r.Result) == 0 && r.ResultHash == ""
	case "COMPLETED":
		return r.ExpiresAt > 0 && len(r.Result) >= j.aead.NonceSize()+j.aead.Overhead() && len(r.Result) <= maxResult+j.aead.NonceSize()+j.aead.Overhead() && equalMAC(r.ResultHash, digest(r.Result))
	}
	return false
}
func resultAAD(r record) []byte {
	b, _ := json.Marshal([]any{"managed-journal-result-v1", r.Key, r.CallID, r.TenantID, r.ActorID, r.AccountID, r.TaskID, r.LogicalID, r.Operation, r.Model, r.Batch, r.InputDigest, r.ExpiresAt})
	return b
}
func valid(s Scope) bool {
	for _, value := range []string{s.TenantID, s.ActorID, s.AccountID, s.TaskID, s.LogicalID, s.Model} {
		if !identity.MatchString(value) {
			return false
		}
	}
	if len(s.PlanDigest) != 64 {
		return false
	}
	if _, err := hex.DecodeString(s.PlanDigest); err != nil {
		return false
	}
	return s.Batch >= 0 && s.Batch <= 1000000 && (s.Operation == "embedding" || s.Operation == "rerank")
}

// Execute persists a call ID and input digest before any network I/O. An
// existing in-flight/unknown record must never invoke send again. send must
// return only an independently verified settled result; failures are ambiguous.
func (j *Journal) Execute(ctx context.Context, s Scope, input []byte, send func(context.Context, string) ([]byte, error)) ([]byte, error) {
	if j == nil || j.db == nil || !valid(s) || len(input) == 0 || len(input) > maxInput || send == nil {
		return nil, ErrInvalid
	}
	// The globally unique logical ID has one immutable owner across all calls.
	// Operation and ordinal select an individual frozen wire request.
	keyBytes, _ := json.Marshal([]any{s.LogicalID, s.Operation, s.Batch})
	key := digest(keyBytes)
	operationBytes, _ := json.Marshal([]string{s.LogicalID, s.Operation})
	operationKey := digest(operationBytes)
	inputDigest := j.mac("input:"+key, input)
	planDigest := j.mac("plan:"+operationKey, []byte(s.PlanDigest))
	// The same immutable work and batch must retain its call identity even if
	// this database is restored to a point before the first local dispatch.
	// Uniqueness of logical work IDs is an upstream admission invariant.
	callID := j.callMAC("managed-journal:call-id:v1", keyBytes)
	candidate := record{Key: key, CallID: "wk_" + callID[:60], TenantID: s.TenantID, ActorID: s.ActorID, AccountID: s.AccountID, TaskID: s.TaskID, LogicalID: s.LogicalID, Operation: s.Operation, Model: s.Model, Batch: s.Batch, InputDigest: inputDigest, Status: "PREPARED"}
	operation := logicalOperation{Key: operationKey, Model: s.Model, PlanDigest: planDigest}
	operation.BindingMAC = j.operationMAC(operation)
	candidate.BindingMAC = j.recordMAC(candidate, operation)
	candidate.StateMAC = j.stateMAC(candidate)
	var inserted bool
	var current record
	err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		owner := logicalOwner{OwnerKey: digest([]byte(s.LogicalID)), LogicalID: s.LogicalID, TenantID: s.TenantID, ActorID: s.ActorID, AccountID: s.AccountID, TaskID: s.TaskID}
		owner.BindingMAC = j.ownerMAC(owner)
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&owner).Error; err != nil {
			return err
		}
		var existing logicalOwner
		if err := tx.First(&existing, "owner_key = ?", owner.OwnerKey).Error; err != nil {
			return err
		}
		if !equalMAC(existing.BindingMAC, j.ownerMAC(existing)) || existing.LogicalID != s.LogicalID || existing.TenantID != s.TenantID || existing.ActorID != s.ActorID || existing.AccountID != s.AccountID || existing.TaskID != s.TaskID {
			return ErrConflict
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&operation).Error; err != nil {
			return err
		}
		var existingOperation logicalOperation
		if err := tx.First(&existingOperation, "operation_key = ?", operation.Key).Error; err != nil {
			return err
		}
		if !equalMAC(existingOperation.BindingMAC, j.operationMAC(existingOperation)) || existingOperation.Model != s.Model || !hmac.Equal([]byte(existingOperation.PlanDigest), []byte(planDigest)) {
			return ErrConflict
		}
		saved := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&candidate)
		if saved.Error != nil {
			return saved.Error
		}
		inserted = saved.RowsAffected == 1
		return tx.First(&current, "request_key = ?", key).Error
	})
	if err != nil {
		return nil, err
	}
	if !equalMAC(current.BindingMAC, j.recordMAC(current, operation)) || !j.validState(current) {
		return nil, ErrUnresolved
	}
	if current.TenantID != s.TenantID || current.ActorID != s.ActorID || current.AccountID != s.AccountID || current.TaskID != s.TaskID || current.Model != s.Model || !hmac.Equal([]byte(current.InputDigest), []byte(inputDigest)) {
		return nil, ErrConflict
	}
	if current.Status == "COMPLETED" {
		if current.ExpiresAt <= j.now().UnixMilli() {
			if _, err := j.expire(ctx, current); err != nil {
				return nil, err
			}
			return nil, ErrExpired
		}
		if len(current.Result) < j.aead.NonceSize()+j.aead.Overhead() || len(current.Result) > maxResult+j.aead.NonceSize()+j.aead.Overhead() || !equalMAC(current.ResultHash, digest(current.Result)) {
			return nil, ErrUnresolved
		}
		plain, err := j.aead.Open(nil, current.Result[:j.aead.NonceSize()], current.Result[j.aead.NonceSize():], resultAAD(current))
		if err != nil || len(plain) == 0 || len(plain) > maxResult {
			return nil, ErrUnresolved
		}
		return plain, nil
	}
	if current.Status == "EXPIRED" {
		return nil, ErrExpired
	}
	// A pre-existing PREPARED record also stays frozen: we cannot prove no
	// concurrent owner is about to dispatch, nor safely infer a crashed state.
	if (!inserted && current.Status != "NOT_SENT") || (current.Status != "PREPARED" && current.Status != "NOT_SENT") {
		return nil, ErrUnresolved
	}
	previousState := current.StateMAC
	previousStatus := current.Status
	current.Status = "DISPATCHED"
	current.StateMAC = j.stateMAC(current)
	dispatched := j.db.WithContext(ctx).Model(&record{}).Where("request_key = ? AND status = ? AND state_mac = ? AND binding_mac = ?", key, previousStatus, previousState, current.BindingMAC).Updates(map[string]any{"status": "DISPATCHED", "state_mac": current.StateMAC})
	if dispatched.Error != nil {
		return nil, dispatched.Error
	}
	if dispatched.RowsAffected != 1 {
		return nil, ErrUnresolved
	}
	result, err := send(ctx, current.CallID)
	if errors.Is(err, ErrDefinitelyNotSent) {
		previousState = current.StateMAC
		current.Status = "NOT_SENT"
		current.StateMAC = j.stateMAC(current)
		saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		saved := j.db.WithContext(saveCtx).Model(&record{}).Where("request_key = ? AND status = ? AND state_mac = ? AND binding_mac = ?", key, "DISPATCHED", previousState, current.BindingMAC).Updates(map[string]any{"status": "NOT_SENT", "state_mac": current.StateMAC})
		if saved.Error != nil || saved.RowsAffected != 1 {
			return nil, ErrUnresolved
		}
		return nil, ErrDefinitelyNotSent
	}
	if err != nil || len(result) == 0 || len(result) > maxResult {
		return nil, ErrUnresolved
	}
	current.ExpiresAt = j.now().Add(j.retention).UnixMilli()
	nonce := make([]byte, j.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrUnresolved
	}
	ciphertext := j.aead.Seal(nonce, nonce, result, resultAAD(current))
	previousState = current.StateMAC
	current.Status = "COMPLETED"
	current.Result = ciphertext
	current.ResultHash = digest(ciphertext)
	current.StateMAC = j.stateMAC(current)
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	finished := j.db.WithContext(saveCtx).Model(&record{}).Where("request_key = ? AND status = ? AND state_mac = ? AND binding_mac = ?", key, "DISPATCHED", previousState, current.BindingMAC).Updates(map[string]any{"status": "COMPLETED", "result": ciphertext, "result_hash": current.ResultHash, "expires_at": current.ExpiresAt, "state_mac": current.StateMAC})
	if finished.Error != nil || finished.RowsAffected != 1 {
		return nil, ErrUnresolved
	}
	return append([]byte(nil), result...), nil
}

// expire removes only the encrypted payload, preserving the immutable ID and
// ownership tombstone so the paid request can never be dispatched again.
func (j *Journal) expire(ctx context.Context, current record) (bool, error) {
	return j.verifyAndExpire(ctx, current, true)
}

func (j *Journal) verifyAndExpire(ctx context.Context, current record, expire bool) (bool, error) {
	var changed bool
	err := j.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		locked := *j
		locked.db = tx
		var err error
		changed, err = locked.expireAuthenticated(ctx, current, expire)
		return err
	})
	return changed, err
}

func (j *Journal) expireAuthenticated(ctx context.Context, current record, expire bool) (bool, error) {
	if current.Status != "COMPLETED" || !j.validState(current) {
		return false, ErrUnresolved
	}
	operationKeyBytes, _ := json.Marshal([]string{current.LogicalID, current.Operation})
	operationKey := digest(operationKeyBytes)
	var operation logicalOperation
	if err := j.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).First(&operation, "operation_key = ?", operationKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, ErrUnresolved
		}
		return false, err
	}
	var owner logicalOwner
	if err := j.db.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).First(&owner, "owner_key = ?", digest([]byte(current.LogicalID))).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, ErrUnresolved
		}
		return false, err
	}
	keyBytes, _ := json.Marshal([]any{current.LogicalID, current.Operation, current.Batch})
	if current.Key != digest(keyBytes) || operation.Model != current.Model || !equalMAC(operation.BindingMAC, j.operationMAC(operation)) || !equalMAC(current.BindingMAC, j.recordMAC(current, operation)) || !equalMAC(owner.BindingMAC, j.ownerMAC(owner)) || owner.LogicalID != current.LogicalID || owner.TenantID != current.TenantID || owner.ActorID != current.ActorID || owner.AccountID != current.AccountID || owner.TaskID != current.TaskID {
		return false, ErrUnresolved
	}
	if _, err := j.aead.Open(nil, current.Result[:j.aead.NonceSize()], current.Result[j.aead.NonceSize():], resultAAD(current)); err != nil {
		return false, ErrUnresolved
	}
	if !expire {
		return false, nil
	}
	original := current
	previousState := current.StateMAC
	current.Status = "EXPIRED"
	current.Result = nil
	current.ResultHash = ""
	current.StateMAC = j.stateMAC(current)
	// Compare every authenticated field, including the ciphertext and its
	// associated owner/operation, so a concurrent change cannot be erased.
	ownerMatch := j.db.Model(&logicalOwner{}).Select("1").Where(map[string]any{"owner_key": owner.OwnerKey, "logical_id": owner.LogicalID, "tenant_id": owner.TenantID, "actor_id": owner.ActorID, "account_id": owner.AccountID, "task_id": owner.TaskID, "binding_mac": owner.BindingMAC})
	operationMatch := j.db.Model(&logicalOperation{}).Select("1").Where(map[string]any{"operation_key": operation.Key, "model": operation.Model, "plan_digest": operation.PlanDigest, "binding_mac": operation.BindingMAC})
	match := map[string]any{"request_key": original.Key, "call_id": original.CallID, "tenant_id": original.TenantID, "actor_id": original.ActorID, "account_id": original.AccountID, "task_id": original.TaskID, "logical_id": original.LogicalID, "operation": original.Operation, "model": original.Model, "batch": original.Batch, "input_digest": original.InputDigest, "binding_mac": original.BindingMAC, "state_mac": previousState, "status": "COMPLETED", "expires_at": original.ExpiresAt, "result_hash": original.ResultHash}
	update := j.db.WithContext(ctx).Model(&record{})
	if j.db.Dialector.Name() == "mysql" {
		// MySQL text columns may use a case- or accent-insensitive collation,
		// while authentication covers their exact bytes.
		for column, value := range match {
			if text, ok := value.(string); ok {
				update = update.Where("BINARY "+column+" = BINARY ?", text)
				delete(match, column)
			}
		}
	}
	saved := update.Where(match).Where("result = ?", original.Result).Where("EXISTS (?)", ownerMatch).Where("EXISTS (?)", operationMatch).Updates(map[string]any{"status": "EXPIRED", "result": nil, "result_hash": "", "state_mac": current.StateMAC})
	if saved.Error != nil {
		return false, saved.Error
	}
	if saved.RowsAffected != 1 {
		var existing record
		if err := j.db.WithContext(ctx).Select("request_key", "binding_mac", "state_mac", "status", "expires_at", "result_hash").First(&existing, "request_key = ?", current.Key).Error; err != nil {
			return false, err
		}
		if existing.Status != "EXPIRED" || existing.BindingMAC != current.BindingMAC || !equalMAC(existing.StateMAC, j.stateMAC(existing)) {
			return false, ErrUnresolved
		}
		return false, nil
	}
	return true, nil
}

// PurgeExpired cleans at most limit payloads. The caller owns scheduling.
func (j *Journal) PurgeExpired(ctx context.Context, limit int) (int64, error) {
	if j == nil || j.db == nil || limit < 1 || limit > 1000 {
		return 0, ErrInvalid
	}
	var cursor journalMeta
	if err := j.db.WithContext(ctx).First(&cursor, 1).Error; err != nil {
		return 0, err
	}
	if !equalMAC(cursor.CursorMAC, j.cursorMAC(cursor)) {
		return 0, ErrUnresolved
	}
	// Audit every record that still holds ciphertext, including rows whose
	// status or expiry has been corrupted. Only keys are paged into memory.
	query := j.db.WithContext(ctx).Select("request_key", "expires_at").Where("result IS NOT NULL")
	if cursor.CursorKey != "" {
		query = query.Where("expires_at > ? OR (expires_at = ? AND request_key > ?)", cursor.CursorExpiry, cursor.CursorExpiry, cursor.CursorKey)
	}
	var rows []record
	if err := query.Order("expires_at, request_key").Limit(limit).Find(&rows).Error; err != nil {
		return 0, err
	}
	var count int64
	corrupt := false
	for _, row := range rows {
		var current record
		err := j.db.WithContext(ctx).First(&current, "request_key = ?", row.Key).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			corrupt = true
		} else if err != nil {
			return count, err
		} else if current.Status == "EXPIRED" && j.validState(current) && current.ExpiresAt == row.ExpiresAt {
			// Another cleaner already removed the same payload.
		} else if current.ExpiresAt != row.ExpiresAt {
			corrupt = true
		} else {
			changed, expireErr := j.verifyAndExpire(ctx, current, current.ExpiresAt <= j.now().UnixMilli())
			if expireErr != nil {
				if !errors.Is(expireErr, ErrUnresolved) {
					return count, expireErr
				}
				corrupt = true
			} else if changed {
				count++
			}
		}
		cursor.CursorExpiry, cursor.CursorKey = row.ExpiresAt, row.Key
	}
	if len(rows) < limit {
		cursor.CursorExpiry, cursor.CursorKey = 0, ""
	}
	previousMAC := cursor.CursorMAC
	if cursor.CursorRevision < 0 || cursor.CursorRevision == math.MaxInt64 {
		return count, ErrUnresolved
	}
	cursor.CursorRevision++
	cursor.CursorMAC = j.cursorMAC(cursor)
	saved := j.db.WithContext(ctx).Model(&journalMeta{}).Where("id = ? AND cursor_mac = ?", 1, previousMAC).Updates(map[string]any{"cursor_expiry": cursor.CursorExpiry, "cursor_key": cursor.CursorKey, "cursor_revision": cursor.CursorRevision, "cursor_mac": cursor.CursorMAC})
	if saved.Error != nil {
		return count, saved.Error
	}
	if saved.RowsAffected != 1 {
		return count, ErrUnresolved
	}
	if corrupt {
		return count, ErrCorrupt
	}
	return count, nil
}

// Info identifies the persisted request for a separately authorized receipt
// reconciliation. It does not provide a redispatch operation.
type Info struct {
	CallID string
	Status string
}

func (j *Journal) Inspect(ctx context.Context, s Scope, input []byte) (Info, error) {
	if j == nil || j.db == nil || !valid(s) || len(input) == 0 || len(input) > maxInput {
		return Info{}, ErrInvalid
	}
	keyBytes, _ := json.Marshal([]any{s.LogicalID, s.Operation, s.Batch})
	operationBytes, _ := json.Marshal([]string{s.LogicalID, s.Operation})
	key, operationKey := digest(keyBytes), digest(operationBytes)
	var current record
	if err := j.db.WithContext(ctx).First(&current, "request_key = ?", key).Error; err != nil {
		return Info{}, err
	}
	var operation logicalOperation
	if err := j.db.WithContext(ctx).First(&operation, "operation_key = ?", operationKey).Error; err != nil {
		return Info{}, err
	}
	var owner logicalOwner
	if err := j.db.WithContext(ctx).First(&owner, "owner_key = ?", digest([]byte(s.LogicalID))).Error; err != nil {
		return Info{}, err
	}
	if !equalMAC(owner.BindingMAC, j.ownerMAC(owner)) || !equalMAC(operation.BindingMAC, j.operationMAC(operation)) || !equalMAC(current.BindingMAC, j.recordMAC(current, operation)) || !j.validState(current) {
		return Info{}, ErrUnresolved
	}
	if owner.LogicalID != s.LogicalID || owner.TenantID != s.TenantID || owner.ActorID != s.ActorID || owner.AccountID != s.AccountID || owner.TaskID != s.TaskID {
		return Info{}, ErrConflict
	}
	if current.TenantID != s.TenantID || current.ActorID != s.ActorID || current.AccountID != s.AccountID || current.TaskID != s.TaskID || current.Model != s.Model || !hmac.Equal([]byte(current.InputDigest), []byte(j.mac("input:"+key, input))) || operation.Model != s.Model || !hmac.Equal([]byte(operation.PlanDigest), []byte(j.mac("plan:"+operationKey, []byte(s.PlanDigest)))) {
		return Info{}, ErrConflict
	}
	if current.Status == "COMPLETED" && current.ExpiresAt <= j.now().UnixMilli() {
		if _, err := j.expire(ctx, current); err != nil {
			return Info{}, err
		}
		current.Status = "EXPIRED"
	}
	return Info{CallID: current.CallID, Status: current.Status}, nil
}

// Recover resolves a previously dispatched call using only an authenticated,
// read-only settled-result lookup. The callback must never submit a provider
// request. Races with a live writer are resolved by state-MAC CAS.
func (j *Journal) Recover(ctx context.Context, s Scope, input []byte, read func(context.Context, string) ([]byte, error)) ([]byte, error) {
	if j == nil || ctx == nil || read == nil {
		return nil, ErrInvalid
	}
	info, err := j.Inspect(ctx, s, input)
	if err != nil {
		return nil, err
	}
	if info.Status != "DISPATCHED" {
		return nil, ErrUnresolved
	}
	result, err := read(ctx, info.CallID)
	if err != nil || len(result) == 0 || len(result) > maxResult || ctx.Err() != nil {
		return nil, ErrUnresolved
	}
	again, err := j.Inspect(ctx, s, input)
	if err != nil || again != info {
		return nil, ErrUnresolved
	}
	keyBytes, _ := json.Marshal([]any{s.LogicalID, s.Operation, s.Batch})
	key := digest(keyBytes)
	var current record
	if err = j.db.WithContext(ctx).First(&current, "request_key = ?", key).Error; err != nil || current.CallID != info.CallID || current.Status != "DISPATCHED" || !j.validState(current) {
		return nil, ErrUnresolved
	}
	opBytes, _ := json.Marshal([]string{s.LogicalID, s.Operation})
	var operation logicalOperation
	var owner logicalOwner
	if j.db.WithContext(ctx).First(&operation, "operation_key = ?", digest(opBytes)).Error != nil ||
		j.db.WithContext(ctx).First(&owner, "owner_key = ?", digest([]byte(s.LogicalID))).Error != nil ||
		!equalMAC(operation.BindingMAC, j.operationMAC(operation)) || !equalMAC(owner.BindingMAC, j.ownerMAC(owner)) ||
		!equalMAC(current.BindingMAC, j.recordMAC(current, operation)) ||
		owner.LogicalID != s.LogicalID || owner.TenantID != s.TenantID || owner.ActorID != s.ActorID || owner.AccountID != s.AccountID || owner.TaskID != s.TaskID ||
		current.LogicalID != s.LogicalID || current.TenantID != s.TenantID || current.ActorID != s.ActorID || current.AccountID != s.AccountID || current.TaskID != s.TaskID || current.Operation != s.Operation || current.Model != s.Model || current.Batch != s.Batch ||
		!hmac.Equal([]byte(current.InputDigest), []byte(j.mac("input:"+key, input))) ||
		operation.Model != s.Model || !hmac.Equal([]byte(operation.PlanDigest), []byte(j.mac("plan:"+operation.Key, []byte(s.PlanDigest)))) {
		return nil, ErrUnresolved
	}
	original := current
	current.ExpiresAt = j.now().Add(j.retention).UnixMilli()
	nonce := make([]byte, j.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrUnresolved
	}
	ciphertext := j.aead.Seal(nonce, nonce, result, resultAAD(current))
	previousState := current.StateMAC
	current.Status = "COMPLETED"
	current.Result = ciphertext
	current.ResultHash = digest(ciphertext)
	current.StateMAC = j.stateMAC(current)
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	ownerMatch := j.db.Model(&logicalOwner{}).Select("1").Where(map[string]any{"owner_key": owner.OwnerKey, "logical_id": owner.LogicalID, "tenant_id": owner.TenantID, "actor_id": owner.ActorID, "account_id": owner.AccountID, "task_id": owner.TaskID, "binding_mac": owner.BindingMAC})
	opMatch := j.db.Model(&logicalOperation{}).Select("1").Where(map[string]any{"operation_key": operation.Key, "model": operation.Model, "plan_digest": operation.PlanDigest, "binding_mac": operation.BindingMAC})
	match := map[string]any{"request_key": original.Key, "call_id": original.CallID, "tenant_id": original.TenantID, "actor_id": original.ActorID, "account_id": original.AccountID, "task_id": original.TaskID, "logical_id": original.LogicalID, "operation": original.Operation, "model": original.Model, "batch": original.Batch, "input_digest": original.InputDigest, "binding_mac": original.BindingMAC, "state_mac": previousState, "status": "DISPATCHED"}
	update := j.db.WithContext(saveCtx).Model(&record{})
	if j.db.Dialector.Name() == "mysql" {
		for column, value := range match {
			if text, ok := value.(string); ok {
				update = update.Where("BINARY "+column+" = BINARY ?", text)
				delete(match, column)
			}
		}
	}
	saved := update.Where(match).Where("EXISTS (?)", ownerMatch).Where("EXISTS (?)", opMatch).Updates(map[string]any{"status": "COMPLETED", "result": ciphertext, "result_hash": current.ResultHash, "expires_at": current.ExpiresAt, "state_mac": current.StateMAC})
	if saved.Error != nil || saved.RowsAffected != 1 {
		return nil, ErrUnresolved
	}
	return append([]byte(nil), result...), nil
}
