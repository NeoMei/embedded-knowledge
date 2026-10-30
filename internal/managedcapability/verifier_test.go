package managedcapability

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) (*Verifier, ed25519.PrivateKey, Claims, Binding, time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Unix(1793290000, 0).UTC()
	v, err := NewVerifier("fixture-issuer", "weknora-document", map[string]ed25519.PublicKey{"key-1": pub}, time.Hour, func() time.Time { return now })
	require.NoError(t, err)
	binding := Binding{EmbeddingModel: EmbeddingModel, EmbeddingSpace: EmbeddingSpace, TenantID: 42, ActorID: "actor", AccountID: "payer", TaskID: "task", WorkID: "work-unique", GrantID: "grant-unique", KnowledgeBaseID: "kb", KnowledgeID: "doc", Purpose: "document-ingest", InputDigest: strings.Repeat("a", 64)}
	claims := Claims{Issuer: "fixture-issuer", Audience: "weknora-document", Binding: binding, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	return v, priv, claims, binding, now
}

func sign(t *testing.T, key ed25519.PrivateKey, kid string, claims Claims) string {
	t.Helper()
	data, err := json.Marshal(claims)
	require.NoError(t, err)
	prefix := "weknora-cap-v1." + kid + "." + base64.RawURLEncoding.EncodeToString(data)
	return prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
}

func TestVerifyBindsTrustedTaskAndRejectsForgery(t *testing.T) {
	v, key, claims, binding, _ := fixture(t)
	token := sign(t, key, "key-1", claims)
	got, err := v.Verify(token, binding)
	require.NoError(t, err)
	require.Equal(t, claims, got)
	// Replay for the same work is needed for recovery, but never for another
	// payer, tenant, task, document, work, grant, operation, or input.
	require.NotEmpty(t, token)
	mutations := []func(*Binding){func(b *Binding) { b.TenantID++ }, func(b *Binding) { b.ActorID = "other" }, func(b *Binding) { b.AccountID = "other" }, func(b *Binding) { b.TaskID = "other" }, func(b *Binding) { b.WorkID = "other" }, func(b *Binding) { b.GrantID = "other" }, func(b *Binding) { b.KnowledgeBaseID = "other" }, func(b *Binding) { b.KnowledgeID = "other" }, func(b *Binding) { b.Purpose = "other" }, func(b *Binding) { b.InputDigest = strings.Repeat("b", 64) }}
	for _, change := range mutations {
		expected := binding
		change(&expected)
		_, err := v.Verify(token, expected)
		require.ErrorIs(t, err, ErrInvalid)
	}
	otherPub, otherKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = otherPub
	_, err = v.Verify(sign(t, otherKey, "key-1", claims), binding)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = v.Verify(sign(t, key, "untrusted-key", claims), binding)
	require.ErrorIs(t, err, ErrInvalid)
	claims.Issuer = "other"
	_, err = v.Verify(sign(t, key, "key-1", claims), binding)
	require.ErrorIs(t, err, ErrInvalid)
}
func TestExpiryAudienceAndCanonicalEncoding(t *testing.T) {
	v, key, claims, binding, now := fixture(t)
	for _, change := range []func(*Claims){func(c *Claims) { c.Audience = "other" }, func(c *Claims) { c.ExpiresAt = now.Unix() }, func(c *Claims) { c.IssuedAt = now.Add(time.Second).Unix() }, func(c *Claims) { c.ExpiresAt = c.IssuedAt + 3601 }, func(c *Claims) { c.IssuedAt = c.ExpiresAt }} {
		copy := claims
		change(&copy)
		_, err := v.Verify(sign(t, key, "key-1", copy), binding)
		require.ErrorIs(t, err, ErrInvalid)
	}
	data, _ := json.Marshal(claims)
	raw := []byte(strings.Replace(string(data), `"issuer":`, `"issuer":"forged","issuer":`, 1))
	prefix := "weknora-cap-v1.key-1." + base64.RawURLEncoding.EncodeToString(raw)
	_, err := v.Verify(prefix+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix))), binding)
	require.ErrorIs(t, err, ErrInvalid)
}
func TestKeyRotationAndInputBounds(t *testing.T) {
	v, key, claims, binding, now := fixture(t)
	token := sign(t, key, "key-1", claims)
	freshPub, freshKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rotated, err := NewVerifier("fixture-issuer", "weknora-document", map[string]ed25519.PublicKey{"key-2": freshPub}, time.Hour, func() time.Time { return now })
	require.NoError(t, err)
	_, err = rotated.Verify(token, binding)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = rotated.Verify(sign(t, freshKey, "key-2", claims), binding)
	require.NoError(t, err)
	_, err = v.Verify(strings.Repeat("A", 16385), binding)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = NewVerifier("https://unihub.example.test", "weknora-document", map[string]ed25519.PublicKey{"key.2": freshPub}, time.Hour, time.Now)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = NewVerifier("https://unihub.example.test", "weknora-document", map[string]ed25519.PublicKey{"key-2": freshPub}, time.Hour, time.Now)
	require.NoError(t, err)
	_, err = NewVerifier("fixture-issuer", "weknora-document", map[string]ed25519.PublicKey{"key-1": {1}}, time.Hour, time.Now)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestVerifierCopiesPublicKeysAndCannotBeReconfiguredByCaller(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Unix(1793290000, 0).UTC()
	keys := map[string]ed25519.PublicKey{"key-1": public}
	v, err := NewVerifier("fixture-issuer", "weknora-document", keys, time.Hour, func() time.Time { return now })
	require.NoError(t, err)
	binding := Binding{EmbeddingModel: EmbeddingModel, EmbeddingSpace: EmbeddingSpace, TenantID: 1, ActorID: "actor", AccountID: "account", TaskID: "task", WorkID: "work", GrantID: "grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", Purpose: "document-ingest", InputDigest: strings.Repeat("a", 64)}
	claims := Claims{Issuer: "fixture-issuer", Audience: "weknora-document", Binding: binding, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	token := sign(t, private, "key-1", claims)
	for i := range public {
		public[i] = 0
	}
	delete(keys, "key-1")
	_, err = v.Verify(token, binding)
	require.NoError(t, err)
}

func TestActiveAuthorizationBindsNonceActorAndExpiry(t *testing.T) {
	verifier, key, _, binding, now := fixture(t)
	nonce := strings.Repeat("c", 64)
	claims := ActiveClaims{Issuer: "fixture-issuer", Audience: "weknora-document", Binding: binding, Nonce: nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix()}
	signActive := func(c ActiveClaims) string {
		data, err := json.Marshal(c)
		require.NoError(t, err)
		prefix := "weknora-auth-v1.key-1." + base64.RawURLEncoding.EncodeToString(data)
		return prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
	}
	token := signActive(claims)
	_, err := verifier.VerifyActive(token, binding, nonce)
	require.NoError(t, err)
	_, err = verifier.VerifyActive(token, binding, strings.Repeat("d", 64))
	require.Error(t, err)
	wrong := binding
	wrong.ActorID = "other"
	_, err = verifier.VerifyActive(token, wrong, nonce)
	require.Error(t, err)
	claims.ExpiresAt = now.Add(31 * time.Second).Unix()
	_, err = verifier.VerifyActive(signActive(claims), binding, nonce)
	require.Error(t, err)
	claims.ExpiresAt = now.Unix()
	_, err = verifier.VerifyActive(signActive(claims), binding, nonce)
	require.Error(t, err)
}
