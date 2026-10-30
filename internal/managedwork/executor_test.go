package managedwork

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/stretchr/testify/require"
)

type fixtureAuthority struct {
	batch   Batch
	revoked bool
}

func (a *fixtureAuthority) Resolve(_ context.Context, workID, operation string, batch int) (Batch, error) {
	if a.revoked || workID != a.batch.Binding.WorkID || operation != a.batch.Operation || batch != a.batch.Ordinal {
		return Batch{}, errors.New("unavailable")
	}
	return a.batch, nil
}
func sum(input []byte) string { h := sha256.Sum256(input); return hex.EncodeToString(h[:]) }
func fixture(t *testing.T) (*Executor, *fixtureAuthority, string, []byte) {
	t.Helper()
	db := testDB(t)
	var err error
	journal, err := managedjournal.Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	verifier, err := managedcapability.NewVerifier("issuer", "weknora-document", map[string]ed25519.PublicKey{"key": pub}, time.Hour, time.Now)
	require.NoError(t, err)
	binding := managedcapability.Binding{EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace, TenantID: 42, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "document", Purpose: "document-ingest", InputDigest: strings.Repeat("a", 64)}
	claims := managedcapability.Claims{Issuer: "issuer", Audience: "weknora-document", Binding: binding, IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	prefix := "weknora-cap-v1.key." + base64.RawURLEncoding.EncodeToString(raw)
	token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(prefix)))
	input := []byte(`{"input":["synthetic"]}`)
	authority := &fixtureAuthority{batch: Batch{Binding: binding, Operation: "embedding", Model: "text-embedding-v4", Ordinal: 0, PlanDigest: sum([]byte("plan")), InputDigest: sum(input)}}
	executor, err := New(verifier, journal, authority, func(context.Context) (string, error) { return "actor", nil }, func(context.Context, string, Batch, []byte) error { return nil })
	require.NoError(t, err)
	return executor, authority, token, input
}
func TestVerifiedWorkUsesOneDurableCallAndRejectsChangedInput(t *testing.T) {
	executor, _, token, input := fixture(t)
	calls := 0
	send := func(_ context.Context, callID string, _ []byte) ([]byte, error) {
		calls++
		require.NotEmpty(t, callID)
		return []byte("settled-result"), nil
	}
	first, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, send)
	require.NoError(t, err)
	second, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, send)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, 1, calls)
	_, err = executor.Execute(context.Background(), token, "work", "embedding", 0, []byte("changed"), send)
	require.Error(t, err)
	require.Equal(t, 1, calls)
}
func TestVerifiedWorkRejectsRevocationAndChangedAuthority(t *testing.T) {
	executor, authority, token, input := fixture(t)
	calls := 0
	send := func(_ context.Context, _ string, _ []byte) ([]byte, error) { calls++; return []byte("settled"), nil }
	original := authority.batch
	for _, change := range []func(*Batch){func(b *Batch) { b.Binding.ActorID = "other" }, func(b *Batch) { b.Binding.AccountID = "other" }, func(b *Batch) { b.Binding.KnowledgeID = "other" }, func(b *Batch) { b.Binding.TaskID = "other" }, func(b *Batch) { b.InputDigest = sum([]byte("other")) }} {
		authority.batch = original
		change(&authority.batch)
		_, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, send)
		require.Error(t, err)
	}
	authority.batch = original
	authority.revoked = true
	_, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, send)
	require.Error(t, err)
	require.Zero(t, calls)
}

func TestRevocationDuringDispatchSuppressesStoredResult(t *testing.T) {
	executor, authority, token, input := fixture(t)
	calls := 0
	send := func(_ context.Context, _ string, _ []byte) ([]byte, error) {
		calls++
		authority.revoked = true
		return []byte("settled"), nil
	}
	result, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, send)
	require.Error(t, err)
	require.Empty(t, result)
	require.Equal(t, 1, calls)
	authority.revoked = false
	result, err = executor.Execute(context.Background(), token, "work", "embedding", 0, input, send)
	require.NoError(t, err)
	require.Equal(t, []byte("settled"), result)
	require.Equal(t, 1, calls)
}

func TestUncertainDispatchRemainsBlockedOnRetry(t *testing.T) {
	executor, _, token, input := fixture(t)
	calls := 0
	send := func(_ context.Context, _ string, _ []byte) ([]byte, error) {
		calls++
		return nil, errors.New("connection closed")
	}
	_, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, send)
	require.ErrorIs(t, err, managedjournal.ErrUnresolved)
	_, err = executor.Execute(context.Background(), token, "work", "embedding", 0, input, send)
	require.ErrorIs(t, err, managedjournal.ErrUnresolved)
	require.Equal(t, 1, calls)
}

func TestLeakedCapabilityCannotReadForDifferentCurrentActor(t *testing.T) {
	executor, _, token, input := fixture(t)
	sent := 0
	sender := func(context.Context, string, []byte) ([]byte, error) { sent++; return []byte("settled"), nil }
	_, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.NoError(t, err)
	executor.currentUser = func(context.Context) (string, error) { return "different-actor", nil }
	result, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.Error(t, err)
	require.Empty(t, result)
	require.Equal(t, 1, sent)
}

func TestIndependentReceiptFailureNeverCachesOrRedelivers(t *testing.T) {
	executor, _, token, input := fixture(t)
	executor.verifyReceipt = func(context.Context, string, Batch, []byte) error { return errors.New("authority mismatch") }
	sends := 0
	sender := func(context.Context, string, []byte) ([]byte, error) { sends++; return []byte("forged"), nil }
	_, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.Error(t, err)
	_, err = executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.Error(t, err)
	require.Equal(t, 1, sends)
}

func TestPreDispatchAuthorizationFailureIsSafeToRetry(t *testing.T) {
	executor, _, token, input := fixture(t)
	checks := 0
	executor.currentUser = func(context.Context) (string, error) {
		checks++
		if checks == 2 {
			return "other", nil
		}
		return "actor", nil
	}
	sends := 0
	sender := func(context.Context, string, []byte) ([]byte, error) { sends++; return []byte("settled"), nil }
	_, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.ErrorIs(t, err, managedjournal.ErrDefinitelyNotSent)
	require.Zero(t, sends)
	result, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.NoError(t, err)
	require.Equal(t, []byte("settled"), result)
	require.Equal(t, 1, sends)
}

func TestSenderCannotClaimNotSent(t *testing.T) {
	executor, _, token, input := fixture(t)
	sends := 0
	sender := func(context.Context, string, []byte) ([]byte, error) {
		sends++
		return nil, managedjournal.ErrDefinitelyNotSent
	}
	_, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.ErrorIs(t, err, managedjournal.ErrUnresolved)
	_, err = executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.ErrorIs(t, err, managedjournal.ErrUnresolved)
	require.Equal(t, 1, sends)
}
