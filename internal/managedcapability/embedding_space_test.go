package managedcapability

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSignedIngestRequiresExplicitEmbeddingSpace(t *testing.T) {
	v, key, claims, _, _ := fixture(t)
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	m["embedding_model"] = "unihub-text-embedding-v4"
	m["embedding_space"] = "aliyun/text-embedding-v4/v4/1024/text"
	signed := func() string {
		b, e := json.Marshal(m)
		require.NoError(t, e)
		p := "weknora-cap-v1.key-1." + base64.RawURLEncoding.EncodeToString(b)
		return p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(p)))
	}
	_, err = v.DecodeVerified(signed())
	require.NoError(t, err)
	delete(m, "embedding_space")
	_, err = v.DecodeVerified(signed())
	require.ErrorIs(t, err, ErrInvalid)
	m["embedding_space"] = "other"
	_, err = v.DecodeVerified(signed())
	require.ErrorIs(t, err, ErrInvalid)
}

func TestSignedSearchRequiresExplicitEmbeddingSpace(t *testing.T) {
	v, key, _, _, now := fixture(t)
	b := SearchBinding{TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: EmbeddingModel, EmbeddingSpace: EmbeddingSpace, RerankModel: "qwen3-rerank"}
	c := SearchClaims{Issuer: "fixture-issuer", Audience: "weknora-document", SearchBinding: b, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	sign := func() string {
		raw, e := json.Marshal(m)
		require.NoError(t, e)
		p := "weknora-search-v1.key-1." + base64.RawURLEncoding.EncodeToString(raw)
		return p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(p)))
	}
	_, err = v.DecodeSearch(sign())
	require.NoError(t, err)
	delete(m, "embedding_space")
	_, err = v.DecodeSearch(sign())
	require.ErrorIs(t, err, ErrInvalid)
	m["embedding_space"] = "aliyun/text-embedding-v4/v4/512/text"
	_, err = v.DecodeSearch(sign())
	require.ErrorIs(t, err, ErrInvalid)
	m["embedding_space"] = EmbeddingSpace
	m["embedding_model"] = "text-embedding-v4"
	_, err = v.DecodeSearch(sign())
	require.ErrorIs(t, err, ErrInvalid)
}
