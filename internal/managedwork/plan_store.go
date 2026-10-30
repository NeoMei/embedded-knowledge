package managedwork

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

var workIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,200}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// The caller constructs a plan from the actual document and immutable batch
// split. Its authorization service must validate the document and selected
// model; this package cannot establish a payer from request fields.
type Plan struct {
	Binding managedcapability.Binding `json:"binding"`
	Batches []PlanBatch               `json:"batches"`
}
type PlanBatch struct {
	Operation   string `json:"operation"`
	Model       string `json:"model"`
	Ordinal     int    `json:"ordinal"`
	InputDigest string `json:"input_digest"`
}

type storedPlan struct {
	WorkID  string `gorm:"primaryKey;size:200"`
	GrantID string `gorm:"uniqueIndex;size:200;not null"`
	Payload string `gorm:"type:text;not null"`
	MAC     string `gorm:"size:64;not null"`
}
type planMeta struct {
	ID       int    `gorm:"primaryKey"`
	Verifier string `gorm:"size:64;not null"`
}

func (storedPlan) TableName() string { return "managed_work_plans" }
func (planMeta) TableName() string   { return "managed_work_plan_meta" }

type PlanStore struct {
	db          *gorm.DB
	key         []byte
	aead        cipher.AEAD
	verifier    *managedcapability.Verifier
	authorize   func(context.Context, managedcapability.Binding, string, string) error
	currentUser func(context.Context) (string, error)
}

func (s *PlanStore) mac(label, value string) string {
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write([]byte(label))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

// The key must be provisioned by the trusted backend and preserved across
// restarts. Losing it must block managed work rather than silently reset it.
func OpenPlanStore(db *gorm.DB, key []byte, verifier *managedcapability.Verifier, authorize func(context.Context, managedcapability.Binding, string, string) error, currentUser func(context.Context) (string, error)) (*PlanStore, error) {
	if db == nil || len(key) != 32 || verifier == nil || authorize == nil || currentUser == nil {
		return nil, ErrUnauthorized
	}
	s := &PlanStore{db: db.Session(&gorm.Session{Logger: logger.Discard}), key: append([]byte(nil), key...), verifier: verifier, authorize: authorize, currentUser: currentUser}
	derived := hmac.New(sha256.New, s.key)
	_, _ = derived.Write([]byte("managed-work-plan-encryption-v1"))
	block, err := aes.NewCipher(derived.Sum(nil))
	if err != nil {
		return nil, ErrUnauthorized
	}
	s.aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if err := s.db.AutoMigrate(&storedPlan{}, &planMeta{}); err != nil {
		return nil, err
	}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		meta := planMeta{ID: 1, Verifier: s.mac("plan-store-verifier-v1", "")}
		var prior planMeta
		if err := tx.First(&prior, 1).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			var existing int64
			if err := tx.Model(&storedPlan{}).Count(&existing).Error; err != nil {
				return err
			}
			if existing != 0 {
				return ErrUnauthorized
			}
		} else if err != nil {
			return err
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&meta).Error; err != nil {
			return err
		}
		var actual planMeta
		if err := tx.First(&actual, 1).Error; err != nil {
			return err
		}
		if !hmac.Equal([]byte(actual.Verifier), []byte(meta.Verifier)) {
			return ErrUnauthorized
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func normalizePlan(plan Plan) (Plan, error) {
	if !workIDPattern.MatchString(plan.Binding.WorkID) || !workIDPattern.MatchString(plan.Binding.GrantID) || len(plan.Batches) == 0 || len(plan.Batches) > 10000 {
		return Plan{}, ErrUnauthorized
	}
	plan.Batches = append([]PlanBatch(nil), plan.Batches...)
	sort.Slice(plan.Batches, func(i, j int) bool {
		if plan.Batches[i].Operation != plan.Batches[j].Operation {
			return plan.Batches[i].Operation < plan.Batches[j].Operation
		}
		return plan.Batches[i].Ordinal < plan.Batches[j].Ordinal
	})
	for i, b := range plan.Batches {
		if (b.Operation != "embedding" && b.Operation != "rerank") || !workIDPattern.MatchString(b.Model) || b.Ordinal < 0 || b.Ordinal > 1000000 || !shaPattern.MatchString(b.InputDigest) {
			return Plan{}, ErrUnauthorized
		}
		if i > 0 && plan.Batches[i-1].Operation == b.Operation && plan.Batches[i-1].Ordinal == b.Ordinal {
			return Plan{}, ErrUnauthorized
		}
	}
	return plan, nil
}

// Admit may only be called after the backend constructs the plan from trusted
// document state. Signature and live authorization are checked before an
// immutable work/grant binding is committed. No token or input is persisted.
func (s *PlanStore) Admit(ctx context.Context, token string, plan Plan) error {
	if s == nil || ctx == nil {
		return ErrUnauthorized
	}
	normalized, err := normalizePlan(plan)
	if err != nil {
		return err
	}
	if _, err = s.verifier.Verify(token, normalized.Binding); err != nil {
		return ErrUnauthorized
	}
	actor, err := s.currentUser(ctx)
	if err != nil || actor == "" || actor != normalized.Binding.ActorID {
		return ErrUnauthorized
	}
	for _, batch := range normalized.Batches {
		if s.authorize(ctx, normalized.Binding, batch.Operation, batch.Model) != nil {
			return ErrUnauthorized
		}
	}
	if ctx.Err() != nil {
		return ErrUnauthorized
	}
	actor, err = s.currentUser(ctx)
	if err != nil || actor != normalized.Binding.ActorID {
		return ErrUnauthorized
	}
	if _, err = s.verifier.Verify(token, normalized.Binding); err != nil {
		return ErrUnauthorized
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	workID, grantID := normalized.Binding.WorkID, normalized.Binding.GrantID
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ErrUnauthorized
	}
	ciphertext := s.aead.Seal(nonce, nonce, raw, []byte(workID+"\x00"+grantID))
	row := storedPlan{WorkID: workID, GrantID: grantID, Payload: base64.RawStdEncoding.EncodeToString(ciphertext)}
	row.MAC = s.mac("plan-v1", row.WorkID+"\x00"+row.GrantID+"\x00"+row.Payload)
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			return err
		}
		var existing storedPlan
		if err := tx.First(&existing, "work_id = ?", row.WorkID).Error; err != nil {
			return ErrUnauthorized
		}
		plain, openErr := s.open(existing)
		if existing.GrantID != row.GrantID || openErr != nil || string(plain) != string(raw) {
			return ErrUnauthorized
		}
		return nil
	})
}

func (s *PlanStore) open(row storedPlan) ([]byte, error) {
	expected := s.mac("plan-v1", row.WorkID+"\x00"+row.GrantID+"\x00"+row.Payload)
	if !hmac.Equal([]byte(row.MAC), []byte(expected)) {
		return nil, ErrUnauthorized
	}
	data, err := base64.RawStdEncoding.DecodeString(row.Payload)
	if err != nil || len(data) < s.aead.NonceSize()+s.aead.Overhead() {
		return nil, ErrUnauthorized
	}
	plain, err := s.aead.Open(nil, data[:s.aead.NonceSize()], data[s.aead.NonceSize():], []byte(row.WorkID+"\x00"+row.GrantID))
	if err != nil {
		return nil, ErrUnauthorized
	}
	return plain, nil
}

func (s *PlanStore) Resolve(ctx context.Context, workID, operation string, ordinal int) (Batch, error) {
	if s == nil || ctx == nil || !workIDPattern.MatchString(workID) {
		return Batch{}, ErrUnauthorized
	}
	var row storedPlan
	if err := s.db.WithContext(ctx).First(&row, "work_id = ?", workID).Error; err != nil {
		return Batch{}, ErrUnauthorized
	}
	plain, err := s.open(row)
	if err != nil {
		return Batch{}, ErrUnauthorized
	}
	var plan Plan
	if json.Unmarshal(plain, &plan) != nil || plan.Binding.WorkID != row.WorkID || plan.Binding.GrantID != row.GrantID {
		return Batch{}, ErrUnauthorized
	}
	normalized, err := normalizePlan(plan)
	if err != nil {
		return Batch{}, err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil || string(canonical) != string(plain) {
		return Batch{}, ErrUnauthorized
	}
	for _, batch := range plan.Batches {
		if batch.Operation == operation && batch.Ordinal == ordinal {
			actor, actorErr := s.currentUser(ctx)
			if actorErr != nil || actor == "" || actor != plan.Binding.ActorID || s.authorize(ctx, plan.Binding, batch.Operation, batch.Model) != nil || ctx.Err() != nil {
				return Batch{}, ErrUnauthorized
			}
			digest := sha256.Sum256(canonical)
			return Batch{Binding: plan.Binding, Operation: batch.Operation, Model: batch.Model, Ordinal: batch.Ordinal, InputDigest: batch.InputDigest, PlanDigest: hex.EncodeToString(digest[:])}, nil
		}
	}
	return Batch{}, errors.New("managed work batch unavailable")
}
