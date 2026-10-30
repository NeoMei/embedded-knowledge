package rerank

import (
	"context"
	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/tracing/langfuse"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type privacyReranker struct{}

func (privacyReranker) GetModelName() string { return "fixture" }
func (privacyReranker) GetModelID() string   { return "id" }
func (privacyReranker) Rerank(context.Context, string, []string) ([]RankResult, error) {
	return []RankResult{{Index: 0, RelevanceScore: 0.987654, Document: DocumentInfo{Text: "SECRET_DOCUMENT"}}}, nil
}
func TestManagedRerankPrivacySubprocess(t *testing.T) {
	if os.Getenv("MANAGED_RERANK_PRIVACY_CHILD") == "1" {
		var exports atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { exports.Add(1); w.WriteHeader(http.StatusOK) }))
		defer server.Close()
		manager, err := langfuse.Init(langfuse.Config{Enabled: true, Host: server.URL, PublicKey: "public", SecretKey: "secret", FlushAt: 1, FlushInterval: time.Second, QueueSize: 100, RequestTimeout: time.Second, SampleRate: 1})
		require.NoError(t, err)
		model := &debugReranker{inner: &langfuseReranker{inner: privacyReranker{}}}
		ctx := context.Background()
		if os.Getenv("MANAGED_RERANK_PRIVACY_MODE") == "managed" {
			ctx = api.WithManagedJSON(ctx, func(context.Context, string, string, []byte) ([]byte, error) { return nil, nil })
		}
		_, err = model.Rerank(ctx, "SECRET_QUERY", []string{"SECRET_DOCUMENT"})
		require.NoError(t, err)
		require.NoError(t, manager.Shutdown(context.Background()))
		entries, err := os.ReadDir(os.Getenv("LLM_DEBUG_LOG"))
		require.NoError(t, err)
		if os.Getenv("MANAGED_RERANK_PRIVACY_MODE") == "managed" {
			require.Empty(t, entries)
			require.Zero(t, exports.Load())
		} else {
			require.NotEmpty(t, entries)
			require.Positive(t, exports.Load())
			content, err := os.ReadFile(filepath.Join(os.Getenv("LLM_DEBUG_LOG"), entries[0].Name()))
			require.NoError(t, err)
			require.Contains(t, string(content), "SECRET_QUERY")
			require.Contains(t, string(content), "SECRET_DOCUMENT")
		}
		return
	}
	for _, mode := range []string{"managed", "native"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestManagedRerankPrivacySubprocess$", "-test.v")
			cmd.Env = append(os.Environ(), "MANAGED_RERANK_PRIVACY_CHILD=1", "MANAGED_RERANK_PRIVACY_MODE="+mode, "LLM_DEBUG_LOG="+dir)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, strings.TrimSpace(string(out)))
		})
	}
}
