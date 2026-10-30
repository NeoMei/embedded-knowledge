package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagedJSONUsesTrustedDispatchWithoutNativeRetry(t *testing.T) {
	nativeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nativeCalls++; w.WriteHeader(500) }))
	defer server.Close()
	endpoint := Endpoint{BaseURL: server.URL, Model: "embedding", Client: server.Client()}
	calls := 0
	ctx := WithManagedJSON(context.Background(), func(_ context.Context, model, url string, body []byte) ([]byte, error) {
		calls++
		require.Equal(t, "embedding", model)
		require.Equal(t, server.URL+"/v1/embeddings", url)
		require.JSONEq(t, `{"input":["test"]}`, string(body))
		return nil, &TransportError{Op: "send", Err: errors.New("unknown")}
	})
	var output map[string]any
	err := endpoint.PostJSONWithRetry(ctx, server.URL+"/v1/embeddings", map[string]any{"input": []string{"test"}}, &output, RetryPolicy{MaxRetries: 3}, "embedding")
	require.Error(t, err)
	require.Equal(t, 1, calls)
	require.Zero(t, nativeCalls)
}

func TestManagedJSONOnlyReturnsValidBoundedResponse(t *testing.T) {
	endpoint := Endpoint{Model: "rerank"}
	var output struct {
		Status string `json:"status"`
	}
	ctx := WithManagedJSON(context.Background(), func(context.Context, string, string, []byte) ([]byte, error) {
		return []byte(`{"status":"settled"}`), nil
	})
	require.NoError(t, endpoint.PostJSON(ctx, "ignored", map[string]any{"query": "test"}, &output))
	require.Equal(t, "settled", output.Status)
	ctx = WithManagedJSON(context.Background(), func(context.Context, string, string, []byte) ([]byte, error) { return []byte("not-json"), nil })
	require.Error(t, endpoint.PostJSON(ctx, "ignored", map[string]any{"query": "test"}, &output))
}
