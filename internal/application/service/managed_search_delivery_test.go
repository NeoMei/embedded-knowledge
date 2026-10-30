package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type managedDeliveryKnowledgeRepo struct{ interfaces.KnowledgeRepository }

func (managedDeliveryKnowledgeRepo) GetKnowledgeByID(context.Context, uint64, string) (*types.Knowledge, error) {
	return &types.Knowledge{ID: "doc", KnowledgeBaseID: "kb", ManagedWorkID: "index-work", ParseStatus: types.ParseStatusCompleted, EnableStatus: "enabled"}, nil
}

type managedDeliveryKBRepo struct {
	interfaces.KnowledgeBaseRepository
	duringSearch func()
}

func (r managedDeliveryKBRepo) GetKnowledgeBaseByIDs(context.Context, []string) ([]*types.KnowledgeBase, error) {
	r.duringSearch()
	store := "store"
	return []*types.KnowledgeBase{{ID: "kb", TenantID: 1, VectorStoreID: &store}}, nil
}

// Exercise the real no-candidates search path: it must not return successful
// results after authority was lost, even when no model call was necessary.
func TestManagedSearchRechecksAuthorityBeforeDelivery(t *testing.T) {
	for _, mode := range []string{"active", "revoked_during_search", "expired_during_search", "expired_during_final_check", "legacy_index", "conflicting_index", "index_changed_during_search"} {
		t.Run(mode, func(t *testing.T) {
			const epoch int64 = 1800000000
			var now atomic.Int64
			now.Store(epoch)
			var revoked atomic.Bool
			var checks atomic.Int32
			var searched bool
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			verifier, err := managedcapability.NewVerifier("issuer", "weknora", map[string]ed25519.PublicKey{"host-v1": pub}, time.Hour, func() time.Time { return time.Unix(now.Load(), 0) })
			require.NoError(t, err)
			binding := managedcapability.SearchBinding{TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace, RerankModel: "qwen3-rerank"}
			sign := func(prefix string, value any) string {
				raw, err := json.Marshal(value)
				require.NoError(t, err)
				encoded := prefix + ".host-v1." + base64.RawURLEncoding.EncodeToString(raw)
				return encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(encoded)))
			}
			capability := sign("weknora-search-v1", managedcapability.SearchClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: binding, IssuedAt: epoch - 1, ExpiresAt: epoch + 10})
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Nonce string `json:"nonce"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				issued := now.Load()
				switch r.URL.Path {
				case "/internal/knowledge-search/authorize":
					count := checks.Add(1)
					if revoked.Load() {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					assertion := sign("weknora-search-auth-v1", managedcapability.SearchActiveClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: binding, Nonce: request.Nonce, IssuedAt: issued, ExpiresAt: issued + 30})
					if mode == "expired_during_final_check" && count == 2 {
						now.Store(epoch + 10)
					}
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": assertion}))
				case "/internal/knowledge-search/snapshot":
					query := []byte("valuation")
					sum := sha256.Sum256(query)
					assertion := sign("weknora-search-snapshot-v1", managedcapability.SearchSnapshotClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: binding, Nonce: request.Nonce, IssuedAt: issued, ExpiresAt: issued + 30, ContentSHA256: hex.EncodeToString(sum[:])})
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": assertion, "content": base64.StdEncoding.EncodeToString(query)}))
				default:
					t.Errorf("Unexpected host request: %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer host.Close()
			authority, err := managedcapability.NewHostAuthority(host.URL+"/internal/knowledge-work/authorize", verifier, host.Client(), []byte("0123456789abcdef0123456789abcdef"))
			require.NoError(t, err)
			db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "registration.db")), &gorm.Config{})
			require.NoError(t, err)
			require.NoError(t, db.AutoMigrate(&managedRegistration{}))
			block, err := aes.NewCipher([]byte("9876543210abcdef9876543210abcdef"))
			require.NoError(t, err)
			aead, err := cipher.NewGCM(block)
			require.NoError(t, err)
			indexBinding := managedcapability.Binding{TenantID: 1, KnowledgeBaseID: "kb", KnowledgeID: "doc", WorkID: "index-work", GrantID: "index-grant", EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace}
			if mode == "legacy_index" {
				indexBinding.EmbeddingSpace = ""
			}
			if mode == "conflicting_index" {
				indexBinding.EmbeddingSpace = "aliyun/text-embedding-v4/v4/512/text"
			}
			raw, err := json.Marshal(indexBinding)
			require.NoError(t, err)
			nonce := make([]byte, aead.NonceSize())
			row := managedRegistration{WorkID: indexBinding.WorkID, KnowledgeID: indexBinding.KnowledgeID, GrantID: indexBinding.GrantID, Ciphertext: base64.RawStdEncoding.EncodeToString(aead.Seal(nonce, nonce, raw, []byte(indexBinding.WorkID)))}
			require.NoError(t, db.Create(&row).Error)
			engine := &fakeRetrieveEngineService{engineType: types.PostgresRetrieverEngineType, support: []types.RetrieverType{types.VectorRetrieverType}}
			svc := &knowledgeBaseService{
				managedWorker: &pilotManagedWorker{verifier: verifier, host: authority, db: db, aead: aead},
				kgRepo:        managedDeliveryKnowledgeRepo{},
				repo: managedDeliveryKBRepo{duringSearch: func() {
					searched = true
					if mode == "revoked_during_search" {
						revoked.Store(true)
					}
					if mode == "expired_during_search" {
						now.Store(epoch + 10)
					}
					if mode == "index_changed_during_search" {
						require.NoError(t, db.Model(&managedRegistration{}).Where("work_id = ?", indexBinding.WorkID).Update("ciphertext", "invalid").Error)
					}
				}},
				modelService:   newRerankModelService(),
				retrieveEngine: &fakeFanoutRegistry{byStore: map[string]interfaces.RetrieveEngineService{"store": engine}},
				ownership:      &fakeOwnership{owned: map[string]uint64{"store": 1}},
			}
			ctx := context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1))
			result, err := svc.ManagedHybridSearch(ctx, "kb", capability)
			if mode == "legacy_index" || mode == "conflicting_index" {
				require.False(t, searched, "unknown or conflicting index space must not reach retrieval")
				require.ErrorIs(t, err, ErrManagedWorkerUnavailable)
				require.Nil(t, result)
				return
			}
			require.True(t, searched)
			if mode == "active" {
				require.NoError(t, err)
				require.NotNil(t, result)
				require.Empty(t, result.Results)
				return
			}
			require.ErrorIs(t, err, ErrManagedWorkerUnavailable)
			require.Nil(t, result, "lost authority must not deliver a successful result")
		})
	}
}
