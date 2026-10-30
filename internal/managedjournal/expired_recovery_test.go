package managedjournal

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func expiredFixture(t *testing.T) (*Journal, Scope, []byte, record) {
	t.Helper()
	j := fixture(t)
	s := scope()
	input := []byte("original immutable input")
	now := time.Now()
	j.now = func() time.Time { return now }
	_, err := j.Execute(context.Background(), s, input, func(context.Context, string) ([]byte, error) { return []byte("settled result"), nil })
	require.NoError(t, err)
	now = now.Add(2 * time.Hour)
	_, err = j.Execute(context.Background(), s, input, func(context.Context, string) ([]byte, error) { t.Error("expiry must not submit"); return nil, nil })
	require.ErrorIs(t, err, ErrExpired)
	var row record
	require.NoError(t, j.db.First(&row).Error)
	require.Equal(t, "EXPIRED", row.Status)
	require.Empty(t, row.Result)
	require.Empty(t, row.ResultHash)
	return j, s, input, row
}

func TestExpiredRecoveryExplicitReadOnlyAndExpiryClipped(t *testing.T) {
	j, s, input, old := expiredFixture(t)
	var reads int
	_, err := j.Recover(context.Background(), s, input, func(context.Context, string) ([]byte, error) { reads++; return []byte("forbidden"), nil })
	require.ErrorIs(t, err, ErrUnresolved)
	require.Zero(t, reads)
	deadline := j.now().Add(10 * time.Second)
	result, err := j.RecoverExpired(context.Background(), s, input, deadline, func(_ context.Context, call string) ([]byte, error) {
		reads++
		require.Equal(t, old.CallID, call)
		return []byte("current verified settled result"), nil
	})
	require.NoError(t, err)
	require.Equal(t, "current verified settled result", string(result))
	require.Equal(t, 1, reads)
	var current record
	require.NoError(t, j.db.First(&current).Error)
	require.Equal(t, old.CallID, current.CallID)
	require.Equal(t, old.BindingMAC, current.BindingMAC)
	require.Equal(t, old.InputDigest, current.InputDigest)
	require.Equal(t, "COMPLETED", current.Status)
	require.Equal(t, deadline.UnixMilli(), current.ExpiresAt)
	require.True(t, j.validState(current))
	require.NotEmpty(t, current.ResultHash)
	cached, err := j.Execute(context.Background(), s, input, func(context.Context, string) ([]byte, error) {
		t.Error("restored cache must not submit")
		return nil, nil
	})
	require.NoError(t, err)
	require.Equal(t, result, cached)
}

func TestExpiredRecoveryRejectsChangedBindingsBeforeRead(t *testing.T) {
	for _, change := range []string{"actor", "payer", "task", "model", "operation", "batch", "plan", "input", "state_mac", "owner_mac", "operation_mac"} {
		t.Run(change, func(t *testing.T) {
			j, s, input, old := expiredFixture(t)
			expected := s
			switch change {
			case "actor":
				expected.ActorID = "other"
			case "payer":
				expected.AccountID = "other"
			case "task":
				expected.TaskID = "other"
			case "model":
				expected.Model = "other"
			case "operation":
				expected.Operation = "rerank"
			case "batch":
				expected.Batch++
			case "plan":
				expected.PlanDigest = digest([]byte("other"))
			case "input":
				input = []byte("changed input")
			case "state_mac":
				require.NoError(t, j.db.Model(&record{}).Where("request_key = ?", old.Key).Update("state_mac", "invalid").Error)
			case "owner_mac":
				require.NoError(t, j.db.Model(&logicalOwner{}).Where("logical_id = ?", s.LogicalID).Update("binding_mac", "invalid").Error)
			case "operation_mac":
				require.NoError(t, j.db.Model(&logicalOperation{}).Where("operation_key = ?", digestJSONOperation(s.LogicalID, s.Operation)).Update("binding_mac", "invalid").Error)
			}
			_, err := j.RecoverExpired(context.Background(), expected, input, j.now().Add(time.Minute), func(context.Context, string) ([]byte, error) {
				t.Error("conflicting or unauthenticated original row must not reach host read")
				return []byte("settled"), nil
			})
			require.Error(t, err)
			var row record
			require.NoError(t, j.db.First(&row).Error)
			require.Equal(t, "EXPIRED", row.Status)
			require.Empty(t, row.Result)
			require.Empty(t, row.ResultHash)
		})
	}
}

func TestExpiredRecoveryRechecksStateAndAuthorityAfterRead(t *testing.T) {
	for _, mode := range []string{"owner", "operation", "state", "expired_authority", "read_error", "empty_result"} {
		t.Run(mode, func(t *testing.T) {
			j, s, input, old := expiredFixture(t)
			deadline := j.now().Add(time.Minute)
			_, err := j.RecoverExpired(context.Background(), s, input, deadline, func(context.Context, string) ([]byte, error) {
				switch mode {
				case "owner":
					require.NoError(t, j.db.Model(&logicalOwner{}).Where("logical_id = ?", s.LogicalID).Update("actor_id", "other").Error)
				case "operation":
					require.NoError(t, j.db.Model(&logicalOperation{}).Where("operation_key = ?", digestJSONOperation(s.LogicalID, s.Operation)).Update("model", "other").Error)
				case "state":
					require.NoError(t, j.db.Model(&record{}).Where("request_key = ?", old.Key).Update("state_mac", "invalid").Error)
				case "expired_authority":
					j.now = func() time.Time { return deadline }
				case "read_error":
					return nil, errors.New("unavailable")
				case "empty_result":
					return nil, nil
				}
				return []byte("settled"), nil
			})
			require.Error(t, err)
			var row record
			require.NoError(t, j.db.First(&row).Error)
			require.Equal(t, "EXPIRED", row.Status)
			require.Empty(t, row.Result)
			require.Empty(t, row.ResultHash)
		})
	}
}

func TestExpiredRecoveryConcurrentRestoreAndRetentionCursor(t *testing.T) {
	j, s, input, old := expiredFixture(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan error, 2)
	var reads atomic.Int32
	for range 2 {
		go func() {
			_, err := j.RecoverExpired(context.Background(), s, input, j.now().Add(time.Minute), func(context.Context, string) ([]byte, error) {
				reads.Add(1)
				entered <- struct{}{}
				<-release
				return []byte("same settled result"), nil
			})
			results <- err
		}()
	}
	<-entered
	<-entered
	_, err := j.PurgeExpired(context.Background(), 10)
	require.NoError(t, err)
	close(release)
	a, b := <-results, <-results
	require.True(t, a == nil || b == nil)
	require.True(t, a != nil || b != nil, "only one CAS may restore this expired version")
	require.EqualValues(t, 2, reads.Load())
	var row record
	require.NoError(t, j.db.First(&row).Error)
	require.Equal(t, old.CallID, row.CallID)
	require.Equal(t, "COMPLETED", row.Status)
	require.True(t, j.validState(row))
	_, err = j.PurgeExpired(context.Background(), 10)
	require.NoError(t, err)
	data, err := j.Execute(context.Background(), s, input, func(context.Context, string) ([]byte, error) {
		t.Error("retention race must never submit")
		return nil, nil
	})
	require.NoError(t, err)
	require.Equal(t, "same settled result", string(data))
}
