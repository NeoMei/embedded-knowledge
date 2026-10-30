package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/require"
)

type imageGuardChunkService struct {
	interfaces.ChunkService
	chunk *types.Chunk
	err   error
}

func TestManagedImageTaskRejectsEvenWhenCancelled(t *testing.T) {
	repo := &orphanKnowledgeRepo{knowledge: &types.Knowledge{ID: "managed", TenantID: 7, KnowledgeBaseID: "kb", ManagedWorkID: "work", ParseStatus: types.ParseStatusCancelled}}
	svc := &ImageMultimodalService{knowledgeRepo: repo}
	drop, err := svc.shouldDropOrphanedMultimodal(context.Background(), &types.ImageMultimodalPayload{KnowledgeID: "managed"})
	require.False(t, drop)
	require.ErrorIs(t, err, asynq.SkipRetry)
}

func TestManagedImageTaskFinalRetryDoesNotFinalize(t *testing.T) {
	knowledge := &types.Knowledge{ID: "managed-final-image", TenantID: 7, KnowledgeBaseID: "kb", ManagedWorkID: "work", ParseStatus: types.ParseStatusCancelled}
	enqueuer := &orphanTaskEnqueuer{}
	svc := &ImageMultimodalService{knowledgeRepo: &orphanKnowledgeRepo{knowledge: knowledge}, taskEnqueuer: enqueuer}
	key := multimodalPendingKey(knowledge.ID)
	liteMultimodalSet(key, 1)
	t.Cleanup(func() { liteMultimodalDel(key) })
	data, err := json.Marshal(types.ImageMultimodalPayload{TenantID: 7, KnowledgeID: knowledge.ID, KnowledgeBaseID: "kb", ImageURL: "private-image"})
	require.NoError(t, err)
	ctx := types.WithTaskRetryMetadata(context.Background(), 3, 3)
	err = svc.Handle(ctx, asynq.NewTask(types.TypeImageMultimodal, data))
	require.ErrorIs(t, err, asynq.SkipRetry)
	require.Empty(t, enqueuer.enqueued)
	liteMultimodalPending.Lock()
	remaining, exists := liteMultimodalPending.counts[key]
	liteMultimodalPending.Unlock()
	require.True(t, exists)
	require.Equal(t, int64(1), remaining)
}

func TestNativeImageGuardDatabaseFailureFinalizesOnlyOnLastAttempt(t *testing.T) {
	for _, tc := range []struct {
		name          string
		retried       int
		wantFinalized bool
	}{{"retry remains", 1, false}, {"final retry", 3, true}} {
		t.Run(tc.name, func(t *testing.T) {
			id := "native-guard-" + tc.name
			key := useLiteCounter(t, id)
			liteMultimodalSet(key, 1)
			readErr := errors.New("chunk database unavailable")
			enqueuer := &orphanTaskEnqueuer{}
			svc := &ImageMultimodalService{
				knowledgeRepo: &orphanKnowledgeRepo{knowledge: &types.Knowledge{ID: id, TenantID: 7, KnowledgeBaseID: "kb"}},
				kbService:     &orphanKBService{kb: &types.KnowledgeBase{ID: "kb"}},
				chunkService:  &imageGuardChunkService{err: readErr}, taskEnqueuer: enqueuer,
			}
			payload := types.ImageMultimodalPayload{TenantID: 7, KnowledgeID: id, KnowledgeBaseID: "kb", ChunkID: "chunk"}
			err := svc.Handle(types.WithTaskRetryMetadata(context.Background(), tc.retried, 3), imageMultimodalTask(t, payload))
			require.ErrorIs(t, err, readErr)
			_, exists := liteCounter(id)
			require.Equal(t, !tc.wantFinalized, exists)
			require.Equal(t, tc.wantFinalized, len(enqueuer.enqueued) == 1)
		})
	}
}

func (s *imageGuardChunkService) GetChunkByID(context.Context, string) (*types.Chunk, error) {
	return s.chunk, s.err
}

func TestImageMultimodalChecksPersistedChunkAndKnowledge(t *testing.T) {
	payload := types.ImageMultimodalPayload{TenantID: 7, KnowledgeID: "native", KnowledgeBaseID: "kb", ChunkID: "chunk"}
	chunks := &imageGuardChunkService{chunk: &types.Chunk{ID: "chunk", TenantID: 7, KnowledgeID: "native", KnowledgeBaseID: "kb"}}
	repo := &orphanKnowledgeRepo{knowledge: &types.Knowledge{ID: "native", TenantID: 7, KnowledgeBaseID: "kb"}}
	svc := &ImageMultimodalService{chunkService: chunks, knowledgeRepo: repo}
	allowed, err := svc.allowNativeImageTask(context.Background(), &payload)
	require.NoError(t, err)
	require.True(t, allowed)
	// Payload's claimed native knowledge must not override the chunk's actual owner.
	chunks.chunk.KnowledgeID = "managed"
	allowed, err = svc.allowNativeImageTask(context.Background(), &payload)
	require.NoError(t, err)
	require.False(t, allowed)
	chunks.chunk.KnowledgeID = "native"
	repo.knowledge.ManagedWorkID = "managed-work"
	allowed, err = svc.allowNativeImageTask(context.Background(), &payload)
	require.NoError(t, err)
	require.False(t, allowed)
	repo.knowledge.ManagedWorkID = ""
	chunks.chunk.KnowledgeBaseID = "other"
	allowed, err = svc.allowNativeImageTask(context.Background(), &payload)
	require.NoError(t, err)
	require.False(t, allowed)
	chunks.chunk.KnowledgeBaseID = "kb"
	chunks.err = errors.New("database unavailable")
	allowed, err = svc.allowNativeImageTask(context.Background(), &payload)
	require.Error(t, err)
	require.False(t, allowed)
}
