package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	"github.com/stretchr/testify/require"
)

type managedWikiChunkProbe struct {
	interfaces.ChunkRepository
	calls int
}

func (p *managedWikiChunkProbe) ListChunksByKnowledgeID(context.Context, uint64, string) ([]*types.Chunk, error) {
	p.calls++
	return nil, nil
}

func TestWikiManagedKnowledgeNeverReadsChunksOrAppliesUpdates(t *testing.T) {
	ctx := context.Background()
	probe := &managedWikiChunkProbe{}
	svc := &wikiIngestService{
		knowledgeSvc: &wikiKnowledgeLookupStub{lookup: func(_ context.Context, id string) (*types.Knowledge, error) {
			if id == "managed" {
				return &types.Knowledge{ID: id, ManagedWorkID: "work", ParseStatus: types.ParseStatusCompleted}, nil
			}
			if id == "unavailable" {
				return nil, errors.New("database unavailable")
			}
			return &types.Knowledge{ID: id, ParseStatus: types.ParseStatusCompleted}, nil
		}},
		chunkRepo: probe,
	}
	payload := WikiIngestPayload{TenantID: 7, KnowledgeBaseID: "kb"}
	result, updates, err := svc.mapOneDocument(ctx, nil, payload, WikiPendingOp{KnowledgeID: "managed", Op: WikiOpIngest}, nil)
	require.NoError(t, err)
	require.Nil(t, result)
	require.Empty(t, updates)
	require.Zero(t, probe.calls, "managed source must be rejected before loading content")
	_, _, err = svc.mapOneDocument(ctx, nil, payload, WikiPendingOp{KnowledgeID: "native", Op: WikiOpIngest}, nil)
	require.NoError(t, err)
	require.Equal(t, 1, probe.calls, "ordinary sources retain their existing path")
	got, err := svc.filterLiveUpdates(ctx, "kb", []SlugUpdate{{Type: "entity", KnowledgeID: "managed"}, {Type: "entity", KnowledgeID: "native"}, {Type: "retract", KnowledgeID: "managed"}})
	require.NoError(t, err)
	require.Equal(t, []SlugUpdate{{Type: "entity", KnowledgeID: "native"}, {Type: "retract", KnowledgeID: "managed"}}, got)
	_, _, err = svc.mapOneDocument(ctx, nil, payload, WikiPendingOp{KnowledgeID: "unavailable", Op: WikiOpIngest}, nil)
	require.Error(t, err)
	require.Equal(t, 1, probe.calls, "lookup failure must not read document")
}
