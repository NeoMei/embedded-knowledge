package managedjournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func fixture(t *testing.T) *Journal {
	t.Helper()
	var db *gorm.DB
	var err error
	if dsn := os.Getenv("MANAGED_JOURNAL_TEST_POSTGRES"); dsn != "" {
		base, openErr := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, openErr)
		schema := "journal_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		require.NoError(t, base.Exec("CREATE SCHEMA "+schema).Error)
		parsed, parseErr := url.Parse(dsn)
		require.NoError(t, parseErr)
		q := parsed.Query()
		q.Set("search_path", schema)
		parsed.RawQuery = q.Encode()
		db, err = gorm.Open(postgres.Open(parsed.String()), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		t.Cleanup(func() {
			connection, _ := db.DB()
			_ = connection.Close()
			require.NoError(t, base.Exec("DROP SCHEMA "+schema+" CASCADE").Error)
			connection, _ = base.DB()
			_ = connection.Close()
		})
	} else {
		db, err = gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "journal.db")), &gorm.Config{})
		require.NoError(t, err)
	}
	j, err := Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	return j
}
func scope() Scope {
	return Scope{TenantID: "tenant-1", ActorID: "actor-1", AccountID: "payer-1", TaskID: "task-1", LogicalID: "logical-1", Operation: "embedding", Model: "qwen-embedding", PlanDigest: digest([]byte("full batch plan")), Batch: 0}
}
func TestJournalPersistsResultAndRejectsOwnershipOrInputChanges(t *testing.T) {
	j := fixture(t)
	s := scope()
	var calls atomic.Int32
	send := func(_ context.Context, id string) ([]byte, error) {
		calls.Add(1)
		require.NotEmpty(t, id)
		return []byte(`{"data":[1]}`), nil
	}
	first, err := j.Execute(context.Background(), s, []byte("canonical batch"), send)
	require.NoError(t, err)
	replay, err := j.Execute(context.Background(), s, []byte("canonical batch"), send)
	require.NoError(t, err)
	require.Equal(t, first, replay)
	require.EqualValues(t, 1, calls.Load())
	other := s
	other.AccountID = "payer-2"
	_, err = j.Execute(context.Background(), other, []byte("canonical batch"), send)
	require.ErrorIs(t, err, ErrConflict)
	_, err = j.Execute(context.Background(), s, []byte("changed batch"), send)
	require.ErrorIs(t, err, ErrConflict)
}
func TestJournalUnknownNeverRedispatchesAfterReopen(t *testing.T) {
	j := fixture(t)
	s := scope()
	calls := 0
	send := func(context.Context, string) ([]byte, error) {
		calls++
		return nil, errors.New("connection dropped after send")
	}
	_, err := j.Execute(context.Background(), s, []byte("input"), send)
	require.ErrorIs(t, err, ErrUnresolved)
	reopened, err := Open(j.db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	_, err = reopened.Execute(context.Background(), s, []byte("input"), send)
	require.ErrorIs(t, err, ErrUnresolved)
	require.Equal(t, 1, calls)
}

func TestEncryptedResultAndKeyedDigests(t *testing.T) {
	j := fixture(t)
	s := scope()
	input, result := []byte("private source content"), []byte("private vector response")
	calls := 0
	send := func(context.Context, string) ([]byte, error) { calls++; return result, nil }
	_, err := j.Execute(context.Background(), s, input, send)
	require.NoError(t, err)
	var stored record
	require.NoError(t, j.db.First(&stored).Error)
	require.NotContains(t, string(stored.Result), string(result))
	require.NotEqual(t, digest(input), stored.InputDigest)
	var operation logicalOperation
	require.NoError(t, j.db.First(&operation).Error)
	require.NotEqual(t, s.PlanDigest, operation.PlanDigest)
	replayed, err := j.Execute(context.Background(), s, input, send)
	require.NoError(t, err)
	require.Equal(t, result, replayed)
	require.Equal(t, 1, calls)
	wrongKey, err := Open(j.db, []byte("fedcba9876543210fedcba9876543210"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.Nil(t, wrongKey)
	require.ErrorIs(t, err, ErrKeyMismatch)
	require.Equal(t, 1, calls)
}

func TestJournalKeyVerifierFailsClosedAcrossNewRequests(t *testing.T) {
	j := fixture(t)
	_, err := j.Execute(context.Background(), scope(), []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("result"), nil })
	require.NoError(t, err)
	other, err := Open(j.db, []byte("fedcba9876543210fedcba9876543210"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.Nil(t, other)
	require.ErrorIs(t, err, ErrKeyMismatch)
	count := int64(0)
	require.NoError(t, j.db.Model(&record{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
}

func TestUnknownRecordBindingTamperingBlocksInspectAndSend(t *testing.T) {
	for _, field := range []string{"call_id", "tenant_id", "actor_id", "account_id", "task_id", "logical_id", "operation", "model", "batch", "input_digest", "status", "expires_at", "result_hash"} {
		t.Run(field, func(t *testing.T) {
			j := fixture(t)
			s := scope()
			calls := 0
			send := func(context.Context, string) ([]byte, error) { calls++; return nil, errors.New("unknown") }
			_, err := j.Execute(context.Background(), s, []byte("input"), send)
			require.ErrorIs(t, err, ErrUnresolved)
			value := any("tampered")
			if field == "batch" || field == "expires_at" {
				value = 1
			}
			require.NoError(t, j.db.Model(&record{}).Where("logical_id = ?", s.LogicalID).Update(field, value).Error)
			_, err = j.Inspect(context.Background(), s, []byte("input"))
			require.Error(t, err)
			_, err = j.Execute(context.Background(), s, []byte("input"), send)
			require.Error(t, err)
			require.Equal(t, 1, calls)
		})
	}
}

func TestLogicalOwnerAndPlanTamperingCannotCreateAnotherPaidBatch(t *testing.T) {
	for _, table := range []string{"owner", "operation"} {
		t.Run(table, func(t *testing.T) {
			j := fixture(t)
			s := scope()
			calls := 0
			send := func(context.Context, string) ([]byte, error) { calls++; return []byte("ok"), nil }
			_, err := j.Execute(context.Background(), s, []byte("batch 0"), send)
			require.NoError(t, err)
			if table == "owner" {
				require.NoError(t, j.db.Model(&logicalOwner{}).Where("logical_id = ?", s.LogicalID).Update("actor_id", "other").Error)
				s.ActorID = "other"
			} else {
				newPlan := digest([]byte("malicious plan"))
				operationBytes, _ := json.Marshal([]string{s.LogicalID, s.Operation})
				require.NoError(t, j.db.Model(&logicalOperation{}).Where("operation_key = ?", digest(operationBytes)).Update("plan_digest", j.mac("plan:"+digest(operationBytes), []byte(newPlan))).Error)
				s.PlanDigest = newPlan
			}
			s.Batch = 1
			_, err = j.Execute(context.Background(), s, []byte("batch 1"), send)
			require.Error(t, err)
			require.Equal(t, 1, calls)
		})
	}
}

func TestUnversionedJournalDataNeverAdopted(t *testing.T) {
	for _, table := range []string{"managed_model_requests", "managed_model_request_owners", "managed_model_request_operations"} {
		t.Run(table, func(t *testing.T) {
			j := fixture(t)
			s := scope()
			_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return nil, errors.New("unknown") })
			require.ErrorIs(t, err, ErrUnresolved)
			for _, candidate := range []string{"managed_model_requests", "managed_model_request_owners", "managed_model_request_operations"} {
				if candidate != table {
					require.NoError(t, j.db.Exec("DELETE FROM "+candidate).Error)
				}
			}
			require.NoError(t, j.db.Exec("DELETE FROM managed_model_journal_meta").Error)
			_, err = Open(j.db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
			require.ErrorIs(t, err, ErrLegacy)
		})
	}
}

func TestSameContentHasDistinctDigestsAndCiphertextCannotMoveBetweenCalls(t *testing.T) {
	j := fixture(t)
	s := scope()
	input := []byte("same input")
	calls := 0
	send := func(context.Context, string) ([]byte, error) { calls++; return []byte("same private result"), nil }
	_, err := j.Execute(context.Background(), s, input, send)
	require.NoError(t, err)
	var first record
	require.NoError(t, j.db.First(&first).Error)
	s.LogicalID = "logical-2"
	_, err = j.Execute(context.Background(), s, input, send)
	require.NoError(t, err)
	var second record
	require.NoError(t, j.db.Where("logical_id = ?", "logical-2").First(&second).Error)
	require.NotEqual(t, first.InputDigest, second.InputDigest)
	require.NotEqual(t, first.Result, second.Result)
	require.NoError(t, j.db.Model(&record{}).Where("request_key = ?", second.Key).Update("result", first.Result).Error)
	_, err = j.Execute(context.Background(), s, input, send)
	require.ErrorIs(t, err, ErrUnresolved)
	require.Equal(t, 2, calls)
}

func TestTamperedCiphertextOrBindingCannotBeReplayed(t *testing.T) {
	for _, field := range []string{"result", "call_id", "expires_at"} {
		t.Run(field, func(t *testing.T) {
			j := fixture(t)
			s := scope()
			calls := 0
			send := func(context.Context, string) ([]byte, error) { calls++; return []byte("sensitive answer"), nil }
			_, err := j.Execute(context.Background(), s, []byte("input"), send)
			require.NoError(t, err)
			var saved record
			require.NoError(t, j.db.First(&saved).Error)
			var replacement any
			switch field {
			case "result":
				saved.Result[len(saved.Result)-1] ^= 1
				replacement = saved.Result
			case "call_id":
				replacement = "wk-tampered"
			case "expires_at":
				replacement = saved.ExpiresAt + 1
			}
			require.NoError(t, j.db.Model(&record{}).Where("request_key = ?", saved.Key).Update(field, replacement).Error)
			_, err = j.Inspect(context.Background(), s, []byte("input"))
			require.ErrorIs(t, err, ErrUnresolved)
			_, err = j.Execute(context.Background(), s, []byte("input"), send)
			require.ErrorIs(t, err, ErrUnresolved)
			require.Equal(t, 1, calls)
		})
	}
}

func TestExpiryPurgesOnlyResultAndNeverDispatchesAgain(t *testing.T) {
	j := fixture(t)
	s := scope()
	calls := 0
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j.now = func() time.Time { return now }
	send := func(context.Context, string) ([]byte, error) { calls++; return []byte("private"), nil }
	_, err := j.Execute(context.Background(), s, []byte("input"), send)
	require.NoError(t, err)
	now = now.Add(time.Hour)
	_, err = j.Execute(context.Background(), s, []byte("input"), send)
	require.ErrorIs(t, err, ErrExpired)
	var saved record
	require.NoError(t, j.db.First(&saved).Error)
	require.Equal(t, "EXPIRED", saved.Status)
	require.Empty(t, saved.Result)
	require.NotEmpty(t, saved.CallID)
	_, err = j.Execute(context.Background(), s, []byte("input"), send)
	require.ErrorIs(t, err, ErrExpired)
	info, err := j.Inspect(context.Background(), s, []byte("input"))
	require.NoError(t, err)
	require.Equal(t, "EXPIRED", info.Status)
	require.Equal(t, 1, calls)
}

func TestExpiredCleanupIsBoundedAndRetainsTombstones(t *testing.T) {
	j := fixture(t)
	s := scope()
	now := time.Now().UTC()
	j.now = func() time.Time { return now }
	for batch := 0; batch < 3; batch++ {
		s.Batch = batch
		_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("result"), nil })
		require.NoError(t, err)
	}
	now = now.Add(time.Hour)
	count, err := j.PurgeExpired(context.Background(), 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	var expired, remaining int64
	require.NoError(t, j.db.Model(&record{}).Where("status = ?", "EXPIRED").Count(&expired).Error)
	require.NoError(t, j.db.Model(&record{}).Where("status = ?", "COMPLETED").Count(&remaining).Error)
	require.EqualValues(t, 2, expired)
	require.EqualValues(t, 1, remaining)
}

func TestExpiredCleanupPagesPastCorruptionAndKeepsSuspiciousRows(t *testing.T) {
	j := fixture(t)
	s := scope()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j.now = func() time.Time { return now }
	for batch := 0; batch < 4; batch++ {
		s.Batch = batch
		_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("private result"), nil })
		require.NoError(t, err)
		now = now.Add(time.Second)
	}
	var corrupt record
	require.NoError(t, j.db.Where("batch = ?", 0).First(&corrupt).Error)
	require.NoError(t, j.db.Model(&record{}).Where("request_key = ?", corrupt.Key).Update("state_mac", "tampered").Error)
	now = now.Add(time.Hour)
	count, err := j.PurgeExpired(context.Background(), 1)
	require.Zero(t, count)
	require.ErrorIs(t, err, ErrCorrupt)
	// A scheduler/process restart must resume after the suspicious first row.
	reopened, err := Open(j.db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	reopened.now = func() time.Time { return now }
	for batch := 1; batch < 4; batch++ {
		count, err = reopened.PurgeExpired(context.Background(), 1)
		require.NoError(t, err)
		require.EqualValues(t, 1, count)
		var row record
		require.NoError(t, j.db.Where("batch = ?", batch).First(&row).Error)
		require.Equal(t, "EXPIRED", row.Status)
	}
	var unchanged record
	require.NoError(t, j.db.Where("batch = ?", 0).First(&unchanged).Error)
	require.Equal(t, "COMPLETED", unchanged.Status)
	require.Equal(t, "tampered", unchanged.StateMAC)
	require.Equal(t, corrupt.Result, unchanged.Result)
}

func TestExpiredCleanupContinuesWithinPageAndReportsCorruption(t *testing.T) {
	j := fixture(t)
	s := scope()
	now := time.Now().UTC()
	j.now = func() time.Time { return now }
	for batch := 0; batch < 3; batch++ {
		s.Batch = batch
		_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("result"), nil })
		require.NoError(t, err)
		now = now.Add(time.Second)
	}
	require.NoError(t, j.db.Model(&record{}).Where("batch = ?", 0).Update("state_mac", "tampered").Error)
	now = now.Add(time.Hour)
	count, err := j.PurgeExpired(context.Background(), 3)
	require.ErrorIs(t, err, ErrCorrupt)
	require.EqualValues(t, 2, count)
	var pending, expired int64
	require.NoError(t, j.db.Model(&record{}).Where("status = ?", "COMPLETED").Count(&pending).Error)
	require.NoError(t, j.db.Model(&record{}).Where("status = ?", "EXPIRED").Count(&expired).Error)
	require.EqualValues(t, 1, pending)
	require.EqualValues(t, 2, expired)
}

func TestCleanupCursorTamperingFailsClosed(t *testing.T) {
	j := fixture(t)
	require.NoError(t, j.db.Model(&journalMeta{}).Where("id = ?", 1).Update("cursor_key", "forged").Error)
	_, err := j.PurgeExpired(context.Background(), 1)
	require.ErrorIs(t, err, ErrUnresolved)
	_, err = Open(j.db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.ErrorIs(t, err, ErrLegacy)
}

func TestOpenRequiresProtectedKeyAndBoundedRetention(t *testing.T) {
	j := fixture(t)
	for _, config := range []struct {
		key []byte
		ttl time.Duration
	}{{nil, time.Hour}, {[]byte("short"), time.Hour}, {make([]byte, 32), 0}, {make([]byte, 32), 31 * 24 * time.Hour}} {
		_, err := Open(j.db, config.key, []byte("abcdef0123456789abcdef0123456789"), config.ttl)
		require.ErrorIs(t, err, ErrInvalid)
	}
}

func TestLegacyPlaintextFailsClosedOnOpen(t *testing.T) {
	j := fixture(t)
	s := scope()
	_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("result"), nil })
	require.NoError(t, err)
	require.NoError(t, j.db.Model(&record{}).Where("logical_id = ?", s.LogicalID).Updates(map[string]any{"result": []byte("legacy plaintext"), "result_digest": digest([]byte("legacy plaintext")), "expires_at": 0}).Error)
	_, err = Open(j.db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.ErrorIs(t, err, ErrLegacy)
}

func TestJournalDoesNotLogDatabaseParametersOrCiphertext(t *testing.T) {
	var captured bytes.Buffer
	noisy := logger.New(log.New(&captured, "", 0), logger.Config{LogLevel: logger.Info, ParameterizedQueries: false})
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "journal.db")), &gorm.Config{Logger: noisy})
	require.NoError(t, err)
	j, err := Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	_, err = j.Execute(context.Background(), scope(), []byte("input-sensitive"), func(context.Context, string) ([]byte, error) { return []byte("output-sensitive"), nil })
	require.NoError(t, err)
	require.Empty(t, captured.String())
}

func TestJournalPostgresRoundTripAndKeyBinding(t *testing.T) {
	dsn := os.Getenv("MANAGED_JOURNAL_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	base, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	schema := "journal_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	require.NoError(t, base.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		require.NoError(t, base.Exec("DROP SCHEMA "+schema+" CASCADE").Error)
		connection, _ := base.DB()
		_ = connection.Close()
	})
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
	db, err := gorm.Open(postgres.Open(parsed.String()), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() { connection, _ := db.DB(); _ = connection.Close() })
	j, err := Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	s := scope()
	calls := 0
	send := func(context.Context, string) ([]byte, error) { calls++; return []byte("postgres-result"), nil }
	first, err := j.Execute(context.Background(), s, []byte("input"), send)
	require.NoError(t, err)
	again, err := j.Execute(context.Background(), s, []byte("input"), send)
	require.NoError(t, err)
	require.Equal(t, first, again)
	require.Equal(t, 1, calls)
	_, err = Open(db, []byte("fedcba9876543210fedcba9876543210"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.ErrorIs(t, err, ErrKeyMismatch)
	require.NoError(t, db.Model(&record{}).Where("logical_id = ? AND batch = ?", s.LogicalID, s.Batch).Update("state_mac", "tampered").Error)
	s.Batch = 1
	_, err = j.Execute(context.Background(), s, []byte("other"), send)
	require.NoError(t, err)
	j.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	// Both rows may have identical expiry milliseconds; the key tiebreaker
	// still advances past whichever entry sorts first.
	for attempt := 0; attempt < 3; attempt++ {
		_, err = j.PurgeExpired(context.Background(), 1)
		require.True(t, err == nil || errors.Is(err, ErrCorrupt))
	}
	var expired int64
	require.NoError(t, db.Model(&record{}).Where("status = ?", "EXPIRED").Count(&expired).Error)
	require.EqualValues(t, 1, expired)
}
func TestJournalFailsClosedWithoutIdentityAndSeparatesBatches(t *testing.T) {
	j := fixture(t)
	s := scope()
	noOwner := s
	noOwner.ActorID = ""
	_, err := j.Execute(context.Background(), noOwner, []byte("x"), func(context.Context, string) ([]byte, error) { t.Fatal("dispatched without identity"); return nil, nil })
	require.ErrorIs(t, err, ErrInvalid)
	var ids []string
	send := func(_ context.Context, id string) ([]byte, error) { ids = append(ids, id); return []byte("ok"), nil }
	_, err = j.Execute(context.Background(), s, []byte("one"), send)
	require.NoError(t, err)
	s.Batch = 1
	_, err = j.Execute(context.Background(), s, []byte("two"), send)
	require.NoError(t, err)
	require.Len(t, ids, 2)
	require.NotEqual(t, ids[0], ids[1])
}

func TestLogicalRequestOwnershipIsFrozenAcrossBatches(t *testing.T) {
	j := fixture(t)
	s := scope()
	send := func(context.Context, string) ([]byte, error) { return []byte("ok"), nil }
	_, err := j.Execute(context.Background(), s, []byte("a"), send)
	require.NoError(t, err)
	for _, change := range []func(*Scope){func(v *Scope) { v.ActorID = "other" }, func(v *Scope) { v.AccountID = "other" }, func(v *Scope) { v.TaskID = "other" }, func(v *Scope) { v.Model = "other" }, func(v *Scope) { v.PlanDigest = digest([]byte("changed plan")) }} {
		other := s
		other.Batch = 1
		change(&other)
		_, err = j.Execute(context.Background(), other, []byte("b"), send)
		require.ErrorIs(t, err, ErrConflict)
	}
}
func TestConcurrentSameBatchNeverDispatchesTwice(t *testing.T) {
	j := fixture(t)
	s := scope()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var calls atomic.Int32
	send := func(context.Context, string) ([]byte, error) {
		calls.Add(1)
		close(started)
		<-release
		return []byte("settled"), nil
	}
	go func() { _, err := j.Execute(context.Background(), s, []byte("a"), send); done <- err }()
	<-started
	_, err := j.Execute(context.Background(), s, []byte("a"), send)
	require.ErrorIs(t, err, ErrUnresolved)
	close(release)
	require.NoError(t, <-done)
	require.EqualValues(t, 1, calls.Load())
}

func TestInspectUnknownRequiresExactOwnerAndReturnsFrozenCallID(t *testing.T) {
	j := fixture(t)
	s := scope()
	var sent string
	_, err := j.Execute(context.Background(), s, []byte("input"), func(_ context.Context, id string) ([]byte, error) { sent = id; return nil, errors.New("lost") })
	require.ErrorIs(t, err, ErrUnresolved)
	info, err := j.Inspect(context.Background(), s, []byte("input"))
	require.NoError(t, err)
	require.Equal(t, sent, info.CallID)
	require.Equal(t, "DISPATCHED", info.Status)
	wrong := s
	wrong.ActorID = "other"
	_, err = j.Inspect(context.Background(), wrong, []byte("input"))
	require.ErrorIs(t, err, ErrConflict)
	_, err = j.Inspect(context.Background(), s, []byte("different"))
	require.ErrorIs(t, err, ErrConflict)
}

func TestCleanupPreservesTamperedCiphertextAndBindingAndAdvances(t *testing.T) {
	for _, field := range []string{"result", "actor_id", "call_id"} {
		t.Run(field, func(t *testing.T) {
			j := fixture(t)
			s := scope()
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			j.now = func() time.Time { return now }
			for batch := 0; batch < 2; batch++ {
				s.Batch = batch
				_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("private"), nil })
				require.NoError(t, err)
				now = now.Add(time.Second)
			}
			var row record
			require.NoError(t, j.db.Where("batch = ?", 0).First(&row).Error)
			var changed any = "tampered"
			if field == "result" {
				changed = append([]byte(nil), row.Result...)
				changed.([]byte)[0] ^= 1
			}
			require.NoError(t, j.db.Model(&record{}).Where("request_key = ?", row.Key).Update(field, changed).Error)
			now = now.Add(time.Hour)
			n, err := j.PurgeExpired(context.Background(), 1)
			require.Zero(t, n)
			require.ErrorIs(t, err, ErrCorrupt)
			n, err = j.PurgeExpired(context.Background(), 1)
			require.NoError(t, err)
			require.EqualValues(t, 1, n)
			var saved record
			require.NoError(t, j.db.Where("batch = ?", 0).First(&saved).Error)
			require.Equal(t, "COMPLETED", saved.Status)
			require.NotEmpty(t, saved.Result)
		})
	}
}

func TestCleanupDoesNotEraseConcurrentCiphertextUpdate(t *testing.T) {
	j := fixture(t)
	s := scope()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j.now = func() time.Time { return now }
	_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("private"), nil })
	require.NoError(t, err)
	var old record
	require.NoError(t, j.db.First(&old).Error)
	mutated := append([]byte(nil), old.Result...)
	mutated[0] ^= 1
	require.NoError(t, j.db.Model(&record{}).Where("request_key = ?", old.Key).Update("result", mutated).Error)
	changed, err := j.expire(context.Background(), old)
	require.False(t, changed)
	require.ErrorIs(t, err, ErrUnresolved)
	var saved record
	require.NoError(t, j.db.First(&saved).Error)
	require.Equal(t, "COMPLETED", saved.Status)
	require.Equal(t, mutated, saved.Result)
}

func TestCleanupDoesNotEraseCiphertextChangedDuringCompareAndSwap(t *testing.T) {
	j := fixture(t)
	if j.db.Dialector.Name() == "sqlite" {
		t.Skip("SQLite read transaction prevents the concurrent writer; stale-snapshot CAS is tested separately")
	}
	s := scope()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j.now = func() time.Time { return now }
	_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("private"), nil })
	require.NoError(t, err)
	var old record
	require.NoError(t, j.db.First(&old).Error)
	mutated := append([]byte(nil), old.Result...)
	mutated[0] ^= 1
	var injectErr error
	injected := false
	require.NoError(t, j.db.Callback().Update().Before("gorm:update").Register("journal_test_concurrent_change", func(tx *gorm.DB) {
		updates, ok := tx.Statement.Dest.(map[string]any)
		if !ok || updates["status"] != "EXPIRED" || injected {
			return
		}
		injected = true
		injectErr = j.db.Exec("UPDATE managed_model_requests SET result = ? WHERE request_key = ?", mutated, old.Key).Error
	}))
	t.Cleanup(func() { _ = j.db.Callback().Update().Remove("journal_test_concurrent_change") })
	changed, err := j.expire(context.Background(), old)
	require.NoError(t, injectErr)
	require.True(t, injected)
	require.False(t, changed)
	require.ErrorIs(t, err, ErrUnresolved)
	var saved record
	require.NoError(t, j.db.First(&saved).Error)
	require.Equal(t, "COMPLETED", saved.Status)
	require.Equal(t, mutated, saved.Result)
}

func TestCleanupPreservesResultWhenOwnerOrPlanIsTampered(t *testing.T) {
	for _, table := range []string{"owner", "operation"} {
		t.Run(table, func(t *testing.T) {
			j := fixture(t)
			s := scope()
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			j.now = func() time.Time { return now }
			for i := 0; i < 2; i++ {
				s.LogicalID = fmt.Sprintf("logical-%d", i)
				_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("private"), nil })
				require.NoError(t, err)
				now = now.Add(time.Second)
			}
			var row record
			require.NoError(t, j.db.Where("logical_id = ?", "logical-0").First(&row).Error)
			if table == "owner" {
				require.NoError(t, j.db.Model(&logicalOwner{}).Where("logical_id = ?", row.LogicalID).Update("actor_id", "tampered").Error)
			} else {
				require.NoError(t, j.db.Model(&logicalOperation{}).Where("model = ?", row.Model).Where("operation_key = ?", digestJSONOperation(row.LogicalID, row.Operation)).Update("model", "tampered").Error)
			}
			now = now.Add(time.Hour)
			n, err := j.PurgeExpired(context.Background(), 1)
			require.Zero(t, n)
			require.ErrorIs(t, err, ErrCorrupt)
			n, err = j.PurgeExpired(context.Background(), 1)
			require.NoError(t, err)
			require.EqualValues(t, 1, n)
			var saved record
			require.NoError(t, j.db.Where("logical_id = ?", row.LogicalID).First(&saved).Error)
			require.Equal(t, "COMPLETED", saved.Status)
			require.Equal(t, row.Result, saved.Result)
		})
	}
}
func digestJSONOperation(logicalID, operation string) string {
	b, _ := json.Marshal([]string{logicalID, operation})
	return digest(b)
}

func TestCleanupAuditsCiphertextWhoseStatusOrExpiryWasTampered(t *testing.T) {
	for _, field := range []string{"status", "expires_at"} {
		t.Run(field, func(t *testing.T) {
			j := fixture(t)
			s := scope()
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			j.now = func() time.Time { return now }
			for i := 0; i < 2; i++ {
				s.LogicalID = fmt.Sprintf("audit-%d", i)
				_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("private"), nil })
				require.NoError(t, err)
			}
			var rows []record
			require.NoError(t, j.db.Order("request_key").Find(&rows).Error)
			require.Len(t, rows, 2)
			var value any = "PREPARED"
			if field == "expires_at" {
				value = int64(0)
			}
			require.NoError(t, j.db.Model(&record{}).Where("request_key = ?", rows[0].Key).Update(field, value).Error)
			now = now.Add(2 * time.Hour)
			n, err := j.PurgeExpired(context.Background(), 1)
			require.Zero(t, n)
			require.ErrorIs(t, err, ErrCorrupt)
			n, err = j.PurgeExpired(context.Background(), 1)
			require.NoError(t, err)
			require.EqualValues(t, 1, n)
			var saved record
			require.NoError(t, j.db.First(&saved, "request_key = ?", rows[0].Key).Error)
			require.Equal(t, rows[0].Result, saved.Result)
		})
	}
}

func TestCleanupDoesNotEraseCaseChangedBindingAfterAuthentication(t *testing.T) {
	j := fixture(t)
	s := scope()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j.now = func() time.Time { return now }
	_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("private"), nil })
	require.NoError(t, err)
	var old record
	require.NoError(t, j.db.First(&old).Error)
	injected := false
	var injectErr error
	require.NoError(t, j.db.Callback().Update().Before("gorm:update").Register("journal_test_case_change", func(tx *gorm.DB) {
		updates, ok := tx.Statement.Dest.(map[string]any)
		if !ok || updates["status"] != "EXPIRED" || injected {
			return
		}
		injected = true
		injectErr = tx.Exec("UPDATE managed_model_requests SET actor_id = UPPER(actor_id) WHERE request_key = ?", old.Key).Error
	}))
	t.Cleanup(func() { _ = j.db.Callback().Update().Remove("journal_test_case_change") })
	changed, err := j.expire(context.Background(), old)
	require.NoError(t, injectErr)
	require.True(t, injected)
	require.False(t, changed)
	require.ErrorIs(t, err, ErrUnresolved)
	var saved record
	require.NoError(t, j.db.First(&saved).Error)
	require.Equal(t, "COMPLETED", saved.Status)
	require.Equal(t, old.Result, saved.Result)
}

func TestCleanupAuditsFutureExpiryAndRetainsValidUnexpiredResult(t *testing.T) {
	j := fixture(t)
	s := scope()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		s.LogicalID = fmt.Sprintf("future-%d", i)
		_, err := j.Execute(context.Background(), s, []byte("input"), func(context.Context, string) ([]byte, error) { return []byte("private"), nil })
		require.NoError(t, err)
	}
	var rows []record
	require.NoError(t, j.db.Order("request_key").Find(&rows).Error)
	require.Len(t, rows, 2)
	require.NoError(t, j.db.Model(&record{}).Where("request_key = ?", rows[0].Key).Update("expires_at", now.Add(24*time.Hour).UnixMilli()).Error)
	n, err := j.PurgeExpired(context.Background(), 1)
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = j.PurgeExpired(context.Background(), 1)
	require.ErrorIs(t, err, ErrCorrupt)
	require.Zero(t, n)
	var saved []record
	require.NoError(t, j.db.Order("request_key").Find(&saved).Error)
	require.Equal(t, rows[0].Result, saved[0].Result)
	require.Equal(t, rows[1].Result, saved[1].Result)
}

func TestDefinitelyNotSentCanRetryWithSameCallID(t *testing.T) {
	j := fixture(t)
	s := scope()
	var first string
	_, err := j.Execute(context.Background(), s, []byte("input"), func(_ context.Context, id string) ([]byte, error) { first = id; return nil, ErrDefinitelyNotSent })
	require.ErrorIs(t, err, ErrDefinitelyNotSent)
	var second string
	got, err := j.Execute(context.Background(), s, []byte("input"), func(_ context.Context, id string) ([]byte, error) { second = id; return []byte("settled"), nil })
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, []byte("settled"), got)
}

func TestRestoredEarlierJournalUsesSameCallID(t *testing.T) {
	first, second := fixture(t), fixture(t)
	s := scope()
	var ids []string
	sender := func(_ context.Context, id string) ([]byte, error) {
		ids = append(ids, id)
		return []byte("settled"), nil
	}
	_, err := first.Execute(context.Background(), s, []byte("input"), sender)
	require.NoError(t, err)
	_, err = second.Execute(context.Background(), s, []byte("input"), sender)
	require.NoError(t, err)
	require.Len(t, ids, 2)
	require.Equal(t, ids[0], ids[1])
}

func TestCallIDRequiresIndependentStableKey(t *testing.T) {
	j := fixture(t)
	s := scope()
	var id string
	_, err := j.Execute(context.Background(), s, []byte("input"), func(_ context.Context, call string) ([]byte, error) { id = call; return []byte("ok"), nil })
	require.NoError(t, err)
	keyBytes, err := json.Marshal([]any{s.LogicalID, s.Operation, s.Batch})
	require.NoError(t, err)
	require.NotEqual(t, "wk_"+digest(keyBytes)[:60], id)
	_, err = Open(j.db, []byte("0123456789abcdef0123456789abcdef"), []byte("0123456789abcdef0123456789abcdef"), time.Hour)
	require.Error(t, err)
	_, err = Open(j.db, []byte("0123456789abcdef0123456789abcdef"), []byte("0123456789fedcba0123456789fedcba"), time.Hour)
	require.Error(t, err)
}

func TestConcurrentNotSentRetriesDispatchOnceAcrossConnections(t *testing.T) {
	j := fixture(t)
	scope := scope()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := j.Execute(ctx, scope, []byte("input"), func(context.Context, string) ([]byte, error) { return nil, ErrDefinitelyNotSent })
	require.ErrorIs(t, err, ErrDefinitelyNotSent)
	sqlDB, err := j.db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan error, 2)
	start := make(chan struct{})
	var sent atomic.Int32
	for i := 0; i < 2; i++ {
		go func() {
			err := j.db.Connection(func(tx *gorm.DB) error {
				local := *j
				local.db = tx
				<-start
				_, err := local.Execute(ctx, scope, []byte("input"), func(context.Context, string) ([]byte, error) {
					sent.Add(1)
					entered <- struct{}{}
					<-release
					return []byte("settled"), nil
				})
				return err
			})
			results <- err
		}()
	}
	close(start)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("no dispatch")
	}
	// The first sender holds its database connection, forcing the competing
	// retry through a different one while the call remains DISPATCHED.
	var rejected error
	select {
	case rejected = <-results:
	case <-ctx.Done():
		close(release)
		t.Fatal("competing retry blocked")
	}
	close(release)
	second := <-results
	require.Error(t, rejected)
	require.NoError(t, second)
	require.EqualValues(t, 1, sent.Load())
}

func TestUnknownRecoveredOnlyByReadWithoutRedispatch(t *testing.T) {
	j := fixture(t)
	scope := scope()
	input := []byte("input")
	sends := 0
	_, err := j.Execute(context.Background(), scope, input, func(context.Context, string) ([]byte, error) { sends++; return nil, errors.New("lost result") })
	require.ErrorIs(t, err, ErrUnresolved)
	info, err := j.Inspect(context.Background(), scope, input)
	require.NoError(t, err)
	reads := 0
	recovered, err := j.Recover(context.Background(), scope, input, func(_ context.Context, callID string) ([]byte, error) {
		reads++
		require.Equal(t, info.CallID, callID)
		return []byte("settled"), nil
	})
	require.NoError(t, err)
	require.Equal(t, []byte("settled"), recovered)
	require.Equal(t, 1, sends)
	require.Equal(t, 1, reads)
	result, err := j.Execute(context.Background(), scope, input, func(context.Context, string) ([]byte, error) { sends++; return nil, errors.New("must not send") })
	require.NoError(t, err)
	require.Equal(t, recovered, result)
	require.Equal(t, 1, sends)
}

func TestRecoveryRejectsBindingChangedDuringResultRead(t *testing.T) {
	for _, target := range []string{"owner", "operation"} {
		t.Run(target, func(t *testing.T) {
			j := fixture(t)
			s := scope()
			input := []byte("input")
			_, err := j.Execute(context.Background(), s, input, func(context.Context, string) ([]byte, error) {
				return nil, errors.New("lost result")
			})
			require.ErrorIs(t, err, ErrUnresolved)
			_, err = j.Recover(context.Background(), s, input, func(context.Context, string) ([]byte, error) {
				if target == "owner" {
					require.NoError(t, j.db.Model(&logicalOwner{}).Where("logical_id = ?", s.LogicalID).Update("actor_id", "other").Error)
				} else {
					require.NoError(t, j.db.Model(&logicalOperation{}).Where("operation_key = ?", digestJSONOperation(s.LogicalID, s.Operation)).Update("model", "other").Error)
				}
				return []byte("settled"), nil
			})
			require.Error(t, err)
			var row record
			require.NoError(t, j.db.Where("logical_id = ?", s.LogicalID).First(&row).Error)
			require.Equal(t, "DISPATCHED", row.Status)
			require.Empty(t, row.Result)
		})
	}
}
