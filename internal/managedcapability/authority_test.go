package managedcapability

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHostAuthorityFreshNonceAndSignedBinding(t *testing.T) {
	verifier, key, _, binding, now := fixture(t)
	calls := 0
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "/internal/knowledge-work/authorize", r.URL.Path)
		var request struct {
			WorkID string `json:"work_id"`
			Nonce  string `json:"nonce"`
		}
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &request))
		sum := sha256.Sum256(raw)
		mac := hmac.New(sha256.New, []byte("0123456789abcdef0123456789abcdef"))
		_, err = fmt.Fprintf(mac, "weknora-callback-v2\n%s\n%s\n%x\n%s\n%s", r.Method, r.URL.Path, sum, request.Nonce, r.Header.Get("X-WeKnora-Worker-Time"))
		require.NoError(t, err)
		require.Equal(t, hex.EncodeToString(mac.Sum(nil)), r.Header.Get("X-WeKnora-Worker-Signature"))
		require.Equal(t, binding.WorkID, request.WorkID)
		require.Len(t, request.Nonce, 64)
		claims := ActiveClaims{Issuer: "fixture-issuer", Audience: "weknora-document", Binding: binding, Nonce: request.Nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix()}
		data, err := json.Marshal(claims)
		require.NoError(t, err)
		prefix := "weknora-auth-v1.key-1." + base64.RawURLEncoding.EncodeToString(data)
		token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": token}))
	}))
	defer host.Close()
	authority, err := NewHostAuthority(host.URL+"/internal/knowledge-work/authorize", verifier, host.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	require.NoError(t, authority.Check(context.Background(), binding))
	require.Equal(t, 1, calls)
	wrong := binding
	wrong.ActorID = "other"
	require.Error(t, authority.Check(context.Background(), wrong))
	_, err = NewHostAuthority("http://localhost:8080/internal/knowledge-work/authorize", verifier, host.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.Error(t, err)
}

func TestSnapshotAcceptsOnlySignedExactBytes(t *testing.T) {
	verifier, key, _, binding, now := fixture(t)
	alter := false
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/internal/knowledge-work/snapshot", r.URL.Path)
		var request struct {
			WorkID string `json:"work_id"`
			Nonce  string `json:"nonce"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		content := []byte("authorized synthetic document")
		digest := sha256.Sum256(content)
		claims := SnapshotClaims{Issuer: "fixture-issuer", Audience: "weknora-document", Binding: binding, Nonce: request.Nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), ContentSHA256: hex.EncodeToString(digest[:])}
		data, err := json.Marshal(claims)
		require.NoError(t, err)
		prefix := "weknora-snapshot-v1.key-1." + base64.RawURLEncoding.EncodeToString(data)
		token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
		if alter {
			content = []byte("altered")
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": token, "content": base64.StdEncoding.EncodeToString(content)}))
	}))
	defer host.Close()
	authority, err := NewHostAuthority(host.URL+"/internal/knowledge-work/authorize", verifier, host.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	got, err := authority.Snapshot(context.Background(), binding)
	require.NoError(t, err)
	require.Equal(t, []byte("authorized synthetic document"), got)
	alter = true
	_, err = authority.Snapshot(context.Background(), binding)
	require.Error(t, err)
}

func TestSettledResultRequiresExactCallAndContent(t *testing.T) {
	verifier, key, _, binding, now := fixture(t)
	nonce := strings.Repeat("c", 64)
	content := []byte(`{"data":[1]}`)
	sum := sha256.Sum256(content)
	claims := ResultClaims{Issuer: "fixture-issuer", Audience: "weknora-document", Binding: binding, Nonce: nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), CallID: "call", Model: "text-embedding-v4", Operation: "embedding", WireOperation: "embeddings.create", Status: "SETTLED", ContentSHA256: hex.EncodeToString(sum[:])}
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	prefix := "weknora-result-v1.key-1." + base64.RawURLEncoding.EncodeToString(raw)
	token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
	_, err = verifier.VerifyResult(token, binding, nonce, "call", "text-embedding-v4", "embedding", "embeddings.create", content)
	require.NoError(t, err)
	_, err = verifier.VerifyResult(token, binding, nonce, "other", "text-embedding-v4", "embedding", "embeddings.create", content)
	require.Error(t, err)
	_, err = verifier.VerifyResult(token, binding, nonce, "call", "text-embedding-v4", "embedding", "embeddings.create", []byte("changed"))
	require.Error(t, err)
}

func TestHostResultReturnsOnlySignedSettledExactResponse(t *testing.T) {
	verifier, key, _, binding, now := fixture(t)
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/internal/knowledge-work/result", r.URL.Path)
		var request struct {
			WorkID string `json:"work_id"`
			Nonce  string `json:"nonce"`
			CallID string `json:"call_id"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		content := []byte(`{"data":[1]}`)
		sum := sha256.Sum256(content)
		claims := ResultClaims{Issuer: "fixture-issuer", Audience: "weknora-document", Binding: binding, Nonce: request.Nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), CallID: request.CallID, Model: "text-embedding-v4", Operation: "embedding", WireOperation: "embeddings.create", Status: "SETTLED", ContentSHA256: hex.EncodeToString(sum[:])}
		data, err := json.Marshal(claims)
		require.NoError(t, err)
		prefix := "weknora-result-v1.key-1." + base64.RawURLEncoding.EncodeToString(data)
		token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": token, "content": base64.StdEncoding.EncodeToString(content)}))
	}))
	defer host.Close()
	authority, err := NewHostAuthority(host.URL+"/internal/knowledge-work/authorize", verifier, host.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	result, err := authority.Result(context.Background(), binding, "call", "text-embedding-v4", "embedding", "embeddings.create")
	require.NoError(t, err)
	require.JSONEq(t, `{"data":[1]}`, string(result))
	_, err = authority.Result(context.Background(), binding, "call", "other-model", "embedding", "embeddings.create")
	require.Error(t, err)
}

func TestHostDispatchRequiresVerifiedSettledResponse(t *testing.T) {
	verifier, key, _, binding, now := fixture(t)
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			WorkID  string `json:"work_id"`
			Nonce   string `json:"nonce"`
			CallID  string `json:"call_id"`
			Content string `json:"content"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		if r.URL.Path == "/internal/knowledge-work/dispatch" {
			require.Equal(t, "input", string(mustBase64(t, request.Content)))
			_, _ = w.Write([]byte(`{"status":"submitted"}`))
			return
		}
		require.Equal(t, "/internal/knowledge-work/result", r.URL.Path)
		content := []byte(`{"data":[1]}`)
		sum := sha256.Sum256(content)
		claims := ResultClaims{Issuer: "fixture-issuer", Audience: "weknora-document", Binding: binding, Nonce: request.Nonce, IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(), CallID: request.CallID, Model: "text-embedding-v4", Operation: "embedding", WireOperation: "embeddings.create", Status: "SETTLED", ContentSHA256: hex.EncodeToString(sum[:])}
		data, err := json.Marshal(claims)
		require.NoError(t, err)
		prefix := "weknora-result-v1.key-1." + base64.RawURLEncoding.EncodeToString(data)
		token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"assertion": token, "content": base64.StdEncoding.EncodeToString(content)}))
	}))
	defer host.Close()
	authority, err := NewHostAuthority(host.URL+"/internal/knowledge-work/authorize", verifier, host.Client(), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	result, err := authority.Dispatch(context.Background(), binding, "call", "text-embedding-v4", []byte("input"))
	require.NoError(t, err)
	require.JSONEq(t, `{"data":[1]}`, string(result))
}
func mustBase64(t *testing.T, s string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return data
}
