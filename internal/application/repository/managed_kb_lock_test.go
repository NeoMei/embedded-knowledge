package repository

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func managedKBLockDB(t *testing.T, dialect string) *gorm.DB {
	t.Helper()
	var dialector gorm.Dialector
	if dialect == "sqlite" {
		dialector = sqlite.Open(filepath.Join(t.TempDir(), "kb.db") + "?_busy_timeout=5000&_journal_mode=WAL")
	} else {
		dsn := os.Getenv("MANAGED_KB_LOCK_TEST_POSTGRES")
		if dsn == "" {
			t.Skip("MANAGED_KB_LOCK_TEST_POSTGRES unset")
		}
		base, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		require.NoError(t, err)
		schema := "kb_lock_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		require.NoError(t, base.Exec("CREATE SCHEMA "+schema).Error)
		parsed, err := url.Parse(dsn)
		require.NoError(t, err)
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		dialector = postgres.Open(parsed.String())
		t.Cleanup(func() {
			require.NoError(t, base.Exec("DROP SCHEMA "+schema+" CASCADE").Error)
			conn, _ := base.DB()
			_ = conn.Close()
		})
	}
	db, err := gorm.Open(dialector, &gorm.Config{})
	require.NoError(t, err)
	conn, err := db.DB()
	require.NoError(t, err)
	conn.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, db.AutoMigrate(&types.KnowledgeBase{}, &types.Knowledge{}))
	require.NoError(t, db.Create(&types.KnowledgeBase{ID: "kb", TenantID: 1}).Error)
	return db
}

func TestManagedKBReferenceAndDeleteTransactions(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			db := managedKBLockDB(t, dialect)
			kr := &knowledgeRepository{db: db}
			br := &knowledgeBaseRepository{db: db}
			candidate := func(id, work string) *types.Knowledge {
				return &types.Knowledge{ID: id, TenantID: 1, KnowledgeBaseID: "kb", FilePath: "ref://same", FolderPath: "folder", ManagedWorkID: work}
			}
			// Hold the same DB lock as a concurrent registration while a separate
			// connection tries to delete. Delete may not pass a live managed row.
			tx := db.Begin()
			require.NoError(t, tx.Error)
			require.NoError(t, lockActiveKnowledgeBase(tx, 1, "kb"))
			require.NoError(t, tx.Create(candidate("managed", "work")).Error)
			result := make(chan error, 1)
			go func() { result <- br.DeleteWithoutManaged(context.Background(), 1, "kb") }()
			select {
			case err := <-result:
				t.Fatalf("delete escaped held KB lock: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			require.NoError(t, tx.Commit().Error)
			require.ErrorIs(t, <-result, ErrManagedKnowledgeConflict)
			_, _, err := kr.CreateReferenceLocked(context.Background(), candidate("native", ""))
			require.ErrorIs(t, err, ErrManagedKnowledgeConflict)
			_, created, err := kr.CreateReferenceLocked(context.Background(), candidate("managed", "work"))
			require.NoError(t, err)
			require.False(t, created)
			var count int64
			require.NoError(t, db.Model(&types.Knowledge{}).Count(&count).Error)
			require.EqualValues(t, 1, count)
			// Folder rename holds the same lock and must see the managed child
			// that committed while it was waiting, before changing native rows.
			require.NoError(t, db.Create(&types.Knowledge{ID: "other", TenantID: 1, KnowledgeBaseID: "kb", FolderPath: "folder"}).Error)
			tx = db.Begin()
			require.NoError(t, tx.Error)
			require.NoError(t, lockActiveKnowledgeBase(tx, 1, "kb"))
			renamed := make(chan error, 1)
			go func() {
				_, err := kr.RenameKnowledgeFolderPath(context.Background(), 1, "kb", "folder", "new")
				renamed <- err
			}()
			select {
			case err := <-renamed:
				t.Fatalf("rename escaped held KB lock: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			require.NoError(t, tx.Commit().Error)
			require.Error(t, <-renamed)
			var native types.Knowledge
			require.NoError(t, db.First(&native, "id = ?", "other").Error)
			require.Equal(t, "folder", native.FolderPath)
			// Once the managed row is removed, deletion commits and any later
			// registration must fail without recreating a document in a dead KB.
			require.NoError(t, db.Where("id = ?", "managed").Delete(&types.Knowledge{}).Error)
			require.NoError(t, br.DeleteWithoutManaged(context.Background(), 1, "kb"))
			_, _, err = kr.CreateReferenceLocked(context.Background(), candidate("later", "work"))
			require.Error(t, err, fmt.Sprint(err))
		})
	}
}

func TestKnowledgeBaseUpdateCannotResurrectDeletedRows(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			db := managedKBLockDB(t, dialect)
			br := &knowledgeBaseRepository{db: db}
			ctx := context.Background()
			var stale types.KnowledgeBase
			require.NoError(t, db.First(&stale, "id = ?", "kb").Error)
			stale.Name = "ordinary update"
			require.NoError(t, br.UpdateKnowledgeBase(ctx, &stale))
			var current types.KnowledgeBase
			require.NoError(t, db.First(&current, "id = ?", "kb").Error)
			require.Equal(t, "ordinary update", current.Name)
			stale.Name = ""
			require.NoError(t, br.UpdateKnowledgeBase(ctx, &stale))
			require.NoError(t, db.First(&current, "id = ?", "kb").Error)
			require.Empty(t, current.Name, "native full update must retain explicit zero values")
			// A stale tenant may not overwrite the live row.
			wrongTenant := stale
			wrongTenant.TenantID = 2
			require.ErrorIs(t, br.UpdateKnowledgeBase(ctx, &wrongTenant), ErrKnowledgeBaseNotFound)
			// Real competing connections: delete takes the row lock and commits
			// before the stale full-row save is allowed to continue.
			tx := db.Begin()
			require.NoError(t, tx.Error)
			require.NoError(t, lockActiveKnowledgeBase(tx, 1, "kb"))
			require.NoError(t, tx.Where("id = ? AND tenant_id = ?", "kb", 1).Delete(&types.KnowledgeBase{}).Error)
			result := make(chan error, 1)
			go func() { result <- br.UpdateKnowledgeBase(ctx, &stale) }()
			select {
			case err := <-result:
				t.Fatalf("stale update escaped lock: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			require.NoError(t, tx.Commit().Error)
			require.ErrorIs(t, <-result, ErrKnowledgeBaseNotFound)
			var deleted types.KnowledgeBase
			require.NoError(t, db.Unscoped().First(&deleted, "id = ?", "kb").Error)
			require.True(t, deleted.DeletedAt.Valid, "stale update must not erase the tombstone")
			missing := stale
			missing.ID = "absent"
			require.ErrorIs(t, br.UpdateKnowledgeBase(ctx, &missing), ErrKnowledgeBaseNotFound)
			var count int64
			require.NoError(t, db.Unscoped().Model(&types.KnowledgeBase{}).Where("id = ?", "absent").Count(&count).Error)
			require.Zero(t, count)
		})
	}
}
