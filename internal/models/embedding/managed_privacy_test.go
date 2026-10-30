package embedding

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/tracing/langfuse"
	"github.com/stretchr/testify/require"
)

type privacyEmbedder struct{ Embedder }

func (privacyEmbedder) GetModelName() string { return "fixture" }
func (privacyEmbedder) GetModelID() string   { return "id" }
func (privacyEmbedder) GetDimensions() int   { return 2 }
func (privacyEmbedder) BatchEmbed(context.Context, []string) ([][]float32, error) {
	return [][]float32{{0.123456, 0.987654}}, nil
}
func TestManagedPrivacySubprocess(t *testing.T) {
	if os.Getenv("MANAGED_PRIVACY_CHILD") == "1" {
		var exports atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { exports.Add(1); w.WriteHeader(http.StatusOK) }))
		defer server.Close()
		cfg := langfuse.Config{Enabled: true, Host: server.URL, PublicKey: "public", SecretKey: "secret", FlushAt: 1, FlushInterval: time.Second, QueueSize: 100, RequestTimeout: time.Second, SampleRate: 1}
		manager, err := langfuse.Init(cfg)
		require.NoError(t, err)
		model := &debugEmbedder{inner: &langfuseEmbedder{inner: privacyEmbedder{}}}
		ctx := context.Background()
		if os.Getenv("MANAGED_PRIVACY_MODE") == "managed" {
			ctx = api.WithManagedJSON(ctx, func(context.Context, string, string, []byte) ([]byte, error) { return nil, nil })
		}
		_, err = model.BatchEmbed(ctx, []string{"SECRET_DOCUMENT_FIXTURE"})
		require.NoError(t, err)
		require.NoError(t, manager.Shutdown(context.Background()))
		entries, err := os.ReadDir(os.Getenv("LLM_DEBUG_LOG"))
		require.NoError(t, err)
		if os.Getenv("MANAGED_PRIVACY_MODE") == "managed" {
			require.Empty(t, entries)
			require.Zero(t, exports.Load())
		} else {
			require.NotEmpty(t, entries)
			require.Positive(t, exports.Load())
			content, err := os.ReadFile(filepath.Join(os.Getenv("LLM_DEBUG_LOG"), entries[0].Name()))
			require.NoError(t, err)
			require.Contains(t, string(content), "SECRET_DOCUMENT_FIXTURE")
			require.Contains(t, string(content), "0.123456")
		}
		return
	}
	for _, mode := range []string{"managed", "native"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestManagedPrivacySubprocess$", "-test.v")
			cmd.Env = append(os.Environ(), "MANAGED_PRIVACY_CHILD=1", "MANAGED_PRIVACY_MODE="+mode, "LLM_DEBUG_LOG="+dir)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, strings.TrimSpace(string(out)))
		})
	}
}
