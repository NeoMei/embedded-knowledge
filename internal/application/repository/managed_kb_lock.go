package repository

import (
	"context"
	"errors"

	"github.com/Tencent/WeKnora/internal/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

var ErrManagedKnowledgeConflict = errors.New("managed knowledge operation unavailable")

// lockActiveKnowledgeBase is shared by reference registration, KB deletion,
// and folder rename. SQLite acquires the write lock before reading; PostgreSQL
// uses a row lock held to transaction completion.
func lockActiveKnowledgeBase(tx *gorm.DB, tenant uint64, id string) error {
	if tenant == 0 || id == "" {
		return ErrManagedKnowledgeConflict
	}
	query := tx.Model(&types.KnowledgeBase{}).Where("tenant_id = ? AND id = ?", tenant, id)
	if tx.Dialector.Name() == "sqlite" {
		result := query.UpdateColumn("updated_at", gorm.Expr("updated_at"))
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrKnowledgeBaseNotFound
		}
		return nil
	}
	if tx.Dialector.Name() != "postgres" {
		return ErrManagedKnowledgeConflict
	}
	var kb types.KnowledgeBase
	if err := query.Select("id").Clauses(clause.Locking{Strength: "UPDATE"}).First(&kb).Error; err != nil {
		return err
	}
	return nil
}

// CreateReferenceLocked returns an existing row only if it has the same
// managed/non-managed ownership; duplicate concurrent registrations serialize.
func (r *knowledgeRepository) CreateReferenceLocked(ctx context.Context, candidate *types.Knowledge) (*types.Knowledge, bool, error) {
	if candidate == nil || candidate.FilePath == "" {
		return nil, false, ErrManagedKnowledgeConflict
	}
	var existing types.Knowledge
	created := false
	err := r.db.WithContext(ctx).Session(&gorm.Session{Logger: logger.Discard}).Transaction(func(tx *gorm.DB) error {
		if err := lockActiveKnowledgeBase(tx, candidate.TenantID, candidate.KnowledgeBaseID); err != nil {
			return err
		}
		err := tx.Where("tenant_id = ? AND knowledge_base_id = ? AND file_path = ? AND parse_status <> ?", candidate.TenantID, candidate.KnowledgeBaseID, candidate.FilePath, "deleting").First(&existing).Error
		if err == nil {
			if (candidate.ManagedWorkID != "" && (existing.ManagedWorkID != candidate.ManagedWorkID || existing.ID != candidate.ID)) || (candidate.ManagedWorkID == "" && existing.ManagedWorkID != "") {
				return ErrManagedKnowledgeConflict
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err := tx.Create(candidate).Error; err != nil {
			return err
		}
		existing = *candidate
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return &existing, created, nil
}

// DeleteWithoutManaged locks the same KB as reference registration and makes
// the managed check and soft delete one atomic transaction.
func (r *knowledgeBaseRepository) DeleteWithoutManaged(ctx context.Context, tenant uint64, id string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockActiveKnowledgeBase(tx, tenant, id); err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&types.Knowledge{}).Where("tenant_id = ? AND knowledge_base_id = ? AND managed_work_id <> ?", tenant, id, "").Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return ErrManagedKnowledgeConflict
		}
		return tx.Where("tenant_id = ? AND id = ?", tenant, id).Delete(&types.KnowledgeBase{}).Error
	})
}

// IsSoftDeleted proves a queued delete refers to a KB whose tombstone has
// already committed. Missing, live, and foreign-tenant KBs cannot be cleaned.
func (r *knowledgeBaseRepository) IsSoftDeleted(ctx context.Context, tenant uint64, id string) (bool, error) {
	if tenant == 0 || id == "" {
		return false, ErrManagedKnowledgeConflict
	}
	var kb types.KnowledgeBase
	if err := r.db.WithContext(ctx).Unscoped().Select("id", "tenant_id", "deleted_at").Where("tenant_id = ? AND id = ?", tenant, id).First(&kb).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return kb.DeletedAt.Valid, nil
}
