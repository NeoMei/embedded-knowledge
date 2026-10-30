package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagedEmbeddingResultRejectsWrongSpaceWidth(t *testing.T) {
	valid, err := json.Marshal(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": make([]float64, 1024)}}})
	require.NoError(t, err)
	require.NoError(t, validateManagedEmbeddingResult(valid))
	wrong, err := json.Marshal(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": make([]float64, 512)}}})
	require.NoError(t, err)
	require.Error(t, validateManagedEmbeddingResult(wrong))
	require.Error(t, validateManagedEmbeddingResult([]byte(`{"data":[]}`)))
}
