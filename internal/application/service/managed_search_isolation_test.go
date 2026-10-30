package service

import (
	"context"
	"testing"

	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
)

func TestUnmanagedSearchCannotReturnManagedDocuments(t *testing.T) {
	hits := []*types.IndexWithScore{{KnowledgeID: "native", ChunkID: "one"}, {KnowledgeID: "managed", ChunkID: "two"}, {KnowledgeID: "missing", ChunkID: "three"}}
	rows := map[string]*types.Knowledge{"native": {ID: "native"}, "managed": {ID: "managed", ManagedWorkID: "work"}}
	got := managedSearchHits(context.Background(), hits, rows)
	require.Len(t, got, 1)
	require.Equal(t, "native", got[0].KnowledgeID)
	ctx := api.WithManagedJSON(context.Background(), func(context.Context, string, string, []byte) ([]byte, error) { return nil, nil })
	got = managedSearchHits(ctx, hits, rows)
	require.Len(t, got, 2)
	require.Equal(t, "managed", got[1].KnowledgeID)
}
