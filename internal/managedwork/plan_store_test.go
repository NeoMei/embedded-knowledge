package managedwork

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("MANAGED_WORK_TEST_POSTGRES")
	if dsn == "" {
		db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "state.db")), &gorm.Config{})
		require.NoError(t, err)
		return db
	}
	base, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	schema := "managedwork_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	require.NoError(t, base.Exec("CREATE SCHEMA "+schema).Error)
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := gorm.Open(postgres.Open(parsed.String()), &gorm.Config{})
	require.NoError(t, err)
	t.Cleanup(func() {
		connection, _ := db.DB()
		_ = connection.Close()
		require.NoError(t, base.Exec("DROP SCHEMA "+schema+" CASCADE").Error)
		connection, _ = base.DB()
		_ = connection.Close()
	})
	return db
}

func TestStorePersistsImmutableVerifiedPlanAndRechecksAuthority(t *testing.T) {
	db := testDB(t)
	var err error
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier, err := managedcapability.NewVerifier("issuer", "weknora-document", map[string]ed25519.PublicKey{"key": public}, time.Hour, time.Now)
	require.NoError(t, err)
	binding := managedcapability.Binding{EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace, TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", Purpose: "document-ingest", InputDigest: strings.Repeat("a", 64)}
	now := time.Now()
	claims := managedcapability.Claims{Issuer: "issuer", Audience: "weknora-document", Binding: binding, IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	prefix := "weknora-cap-v1.key." + base64.RawURLEncoding.EncodeToString(raw)
	token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(prefix)))
	allowed := true
	authorize := func(_ context.Context, b managedcapability.Binding, operation, model string) error {
		if !allowed || b != binding || operation != "embedding" || model != "text-embedding-v4" {
			return ErrUnauthorized
		}
		return nil
	}
	key := []byte("9876543210abcdef9876543210abcdef")
	store, err := OpenPlanStore(db, key, verifier, authorize, func(context.Context) (string, error) { return "actor", nil })
	require.NoError(t, err)
	plan := Plan{Binding: binding, Batches: []PlanBatch{{Operation: "embedding", Model: "text-embedding-v4", Ordinal: 0, InputDigest: sum([]byte("batch"))}}}
	require.NoError(t, store.Admit(context.Background(), token, plan))
	var persisted storedPlan
	require.NoError(t, db.First(&persisted, "work_id = ?", "work").Error)
	require.NotContains(t, persisted.Payload, plan.Binding.InputDigest)
	require.NotContains(t, persisted.Payload, plan.Batches[0].InputDigest)
	reopened, err := OpenPlanStore(db, key, verifier, authorize, func(context.Context) (string, error) { return "actor", nil })
	require.NoError(t, err)
	batch, err := reopened.Resolve(context.Background(), "work", "embedding", 0)
	require.NoError(t, err)
	require.Equal(t, binding, batch.Binding)
	require.Equal(t, sum([]byte("batch")), batch.InputDigest)
	changed := plan
	changed.Binding.AccountID = "other"
	require.Error(t, reopened.Admit(context.Background(), token, changed))
	_, err = OpenPlanStore(db, []byte("different-key-different-key-1234"), verifier, authorize, func(context.Context) (string, error) { return "actor", nil })
	require.Error(t, err)
	allowed = false
	_, err = reopened.Resolve(context.Background(), "work", "embedding", 0)
	require.Error(t, err)
	allowed = true
	require.NoError(t, db.Model(&storedPlan{}).Where("work_id = ?", "work").Update("payload", `{"tampered":true}`).Error)
	_, err = reopened.Resolve(context.Background(), "work", "embedding", 0)
	require.Error(t, err)
}

func TestStoreFailsClosedWhenVerifierIsMissingButPlansExist(t *testing.T) {
	db := testDB(t)
	var err error
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier, err := managedcapability.NewVerifier("issuer", "weknora-document", map[string]ed25519.PublicKey{"key": public}, time.Hour, time.Now)
	require.NoError(t, err)
	authorize := func(context.Context, managedcapability.Binding, string, string) error { return nil }
	key := []byte("9876543210abcdef9876543210abcdef")
	_, err = OpenPlanStore(db, key, verifier, authorize, func(context.Context) (string, error) { return "actor", nil })
	require.NoError(t, err)
	require.NoError(t, db.Create(&storedPlan{WorkID: "existing", GrantID: "grant", Payload: "{}", MAC: "x"}).Error)
	require.NoError(t, db.Delete(&planMeta{}, 1).Error)
	_, err = OpenPlanStore(db, key, verifier, authorize, func(context.Context) (string, error) { return "actor", nil })
	require.Error(t, err)
}

func TestPersistedPlanRunsOneSettledBatchAcrossRestartAndRevocation(t *testing.T) {
	db := testDB(t)
	var err error
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier, err := managedcapability.NewVerifier("issuer", "weknora-document", map[string]ed25519.PublicKey{"key": public}, time.Hour, time.Now)
	require.NoError(t, err)
	binding := managedcapability.Binding{EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace, TenantID: 9, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", Purpose: "document-ingest", InputDigest: strings.Repeat("a", 64)}
	now := time.Now()
	claims := managedcapability.Claims{Issuer: "issuer", Audience: "weknora-document", Binding: binding, IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	prefix := "weknora-cap-v1.key." + base64.RawURLEncoding.EncodeToString(raw)
	token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(prefix)))
	allowed := true
	authorize := func(_ context.Context, b managedcapability.Binding, operation, model string) error {
		if !allowed || b != binding || operation != "embedding" || model != "text-embedding-v4" {
			return ErrUnauthorized
		}
		return nil
	}
	key := []byte("9876543210abcdef9876543210abcdef")
	journalKey := []byte("0123456789abcdef0123456789abcdef")
	planStore, err := OpenPlanStore(db, key, verifier, authorize, func(context.Context) (string, error) { return "actor", nil })
	require.NoError(t, err)
	input := []byte("synthetic batch")
	require.NoError(t, planStore.Admit(context.Background(), token, Plan{Binding: binding, Batches: []PlanBatch{{Operation: "embedding", Model: "text-embedding-v4", Ordinal: 0, InputDigest: sum(input)}}}))
	journal, err := managedjournal.Open(db, journalKey, []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	executor, err := New(verifier, journal, planStore, func(context.Context) (string, error) { return "actor", nil }, func(context.Context, string, Batch, []byte) error { return nil })
	require.NoError(t, err)
	sends := 0
	sender := func(_ context.Context, call string, _ []byte) ([]byte, error) {
		sends++
		require.NotEmpty(t, call)
		return []byte("settled-result"), nil
	}
	first, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.NoError(t, err)
	planStore, err = OpenPlanStore(db, key, verifier, authorize, func(context.Context) (string, error) { return "actor", nil })
	require.NoError(t, err)
	journal, err = managedjournal.Open(db, journalKey, []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	executor, err = New(verifier, journal, planStore, func(context.Context) (string, error) { return "actor", nil }, func(context.Context, string, Batch, []byte) error { return nil })
	require.NoError(t, err)
	second, err := executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, 1, sends)
	allowed = false
	_, err = executor.Execute(context.Background(), token, "work", "embedding", 0, input, sender)
	require.Error(t, err)
	require.Equal(t, 1, sends)
}
