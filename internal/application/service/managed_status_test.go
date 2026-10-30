package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestManagedStatusRequiresFreshBoundProof(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	v, err := managedcapability.NewVerifier("issuer", "weknora", map[string]ed25519.PublicKey{"host-v1": pub}, time.Hour, time.Now)
	require.NoError(t, err)
	binding := managedcapability.Binding{EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace, TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", Purpose: "document-ingest", InputDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	sign := func(kind string, claims any) string {
		b, e := json.Marshal(claims)
		require.NoError(t, e)
		msg := kind + ".host-v1." + base64.RawURLEncoding.EncodeToString(b)
		return msg + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	}
	live := true
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !live {
			w.WriteHeader(403)
			return
		}
		var in struct {
			Nonce string `json:"nonce"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
		n := time.Now().Unix()
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": sign("weknora-auth-v1", managedcapability.ActiveClaims{Issuer: "issuer", Audience: "weknora", Binding: binding, Nonce: in.Nonce, IssuedAt: n, ExpiresAt: n + 30})}))
	}))
	defer host.Close()
	h, err := managedcapability.NewHostAuthority(host.URL+"/internal/knowledge-work/authorize", v, host.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "db")), &gorm.Config{})
	require.NoError(t, err)
	j, err := managedjournal.Open(db, []byte("0123456789abcdef0123456789abcdef"), []byte("abcdef0123456789abcdef0123456789"), time.Hour)
	require.NoError(t, err)
	worker, err := newPilotManagedWorker(db, v, h, j, []byte("9876543210abcdef9876543210abcdef"))
	require.NoError(t, err)
	raw, err := json.Marshal(binding)
	require.NoError(t, err)
	nonce := make([]byte, worker.aead.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	sealed := worker.aead.Seal(nonce, nonce, raw, []byte(binding.WorkID))
	require.NoError(t, db.Create(&managedRegistration{WorkID: binding.WorkID, KnowledgeID: binding.KnowledgeID, GrantID: binding.GrantID, Ciphertext: base64.RawStdEncoding.EncodeToString(sealed)}).Error)
	now := time.Now().Unix()
	cap := sign("weknora-cap-v1", managedcapability.Claims{Issuer: "issuer", Audience: "weknora", Binding: binding, IssuedAt: now, ExpiresAt: now + 60})
	body, _ := json.Marshal(map[string]string{"capability": cap})
	sum := sha256.Sum256(body)
	path := "/api/v1/knowledge-bases/kb/knowledge/managed-status"
	proof := sign("weknora-request-v1", managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: path, BodySHA256: hex.EncodeToString(sum[:]), Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", WorkID: binding.WorkID, ActorID: binding.ActorID, AccountID: binding.AccountID, IssuedAt: now, ExpiresAt: now + 30})
	repo := &summaryColumnsRepo{t: t, knowledge: &types.Knowledge{ID: "doc", TenantID: 1, KnowledgeBaseID: "kb", ManagedWorkID: "work", ParseStatus: types.ParseStatusCompleted}}
	s := &knowledgeService{repo: repo, managedWorker: worker}
	out, err := s.ManagedKnowledgeStatus(context.Background(), 1, "kb", "POST", path, body, cap, proof)
	require.NoError(t, err)
	require.Equal(t, "doc", out.ID)
	require.Equal(t, types.ParseStatusCompleted, out.ParseStatus)
	_, err = s.ManagedKnowledgeStatus(context.Background(), 1, "kb", "POST", path, body, cap, proof)
	require.Error(t, err, "replayed proof")
	_, err = s.ManagedKnowledgeStatus(context.Background(), 1, "kb", "POST", path, append(body, ' '), cap, proof)
	require.Error(t, err, "altered body")
	fresh := sign("weknora-request-v1", managedcapability.RequestClaims{Issuer: "issuer", Audience: "weknora", Method: "POST", Path: path, BodySHA256: hex.EncodeToString(sum[:]), Nonce: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", WorkID: binding.WorkID, ActorID: binding.ActorID, AccountID: binding.AccountID, IssuedAt: now, ExpiresAt: now + 30})
	_, err = s.ManagedKnowledgeStatus(context.Background(), 1, "kb", "POST", path+"/other", body, cap, fresh)
	require.Error(t, err, "proof cannot move to another path")
	live = false
	_, err = s.ManagedKnowledgeStatus(context.Background(), 1, "kb", "POST", path, body, cap, fresh)
	require.Error(t, err, "source no longer authorized")
}
