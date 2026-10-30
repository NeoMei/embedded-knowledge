package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/require"
)

type managedPostCompletionKB struct {
	*wikiEnqueueFailureKBService
	knowledge *types.Knowledge
}

func (s *managedPostCompletionKB) CompleteManagedIndex(context.Context, string) error {
	s.knowledge.ParseStatus = types.ParseStatusCompleted
	s.knowledge.SummaryStatus = types.SummaryStatusNone
	return nil
}
func TestManagedPostProcessSkipsAllUnapprovedEnrichment(t *testing.T) {
	t.Setenv("NEO4J_ENABLE", "true")
	knowledge := &types.Knowledge{ID: "doc", TenantID: 7, KnowledgeBaseID: "kb", ManagedWorkID: "work", ParseStatus: types.ParseStatusProcessing}
	repo := &optionalSummaryKnowledgeRepo{wikiEnqueueFailureKnowledgeRepo: wikiEnqueueFailureKnowledgeRepo{knowledge: knowledge}}
	queue := &wikiEnqueueFailureTaskQueue{}
	kb := &types.KnowledgeBase{ID: "kb", TenantID: 7, Type: types.KnowledgeBaseTypeDocument, IndexingStrategy: types.IndexingStrategy{VectorEnabled: true, GraphEnabled: true, WikiEnabled: true}, QuestionGenerationConfig: &types.QuestionGenerationConfig{Enabled: true}, ExtractConfig: &types.ExtractConfig{Enabled: true}, AutoTagConfig: &types.AutoTagConfig{Enabled: true}}
	svc := &KnowledgePostProcessService{knowledgeRepo: repo, kbService: &managedPostCompletionKB{wikiEnqueueFailureKBService: &wikiEnqueueFailureKBService{kb: kb}, knowledge: knowledge}, chunkRepo: &wikiEnqueueFailureChunkRepo{chunks: []*types.Chunk{{ID: "chunk", TenantID: 7, KnowledgeID: "doc", KnowledgeBaseID: "kb", ChunkType: types.ChunkTypeText, Content: "private document"}}}, taskEnqueuer: queue, pendingRepo: &wikiEnqueueFailurePendingRepo{knowledgeRepo: &repo.wikiEnqueueFailureKnowledgeRepo}}
	body, err := json.Marshal(types.KnowledgePostProcessPayload{TenantID: 7, KnowledgeID: "doc", KnowledgeBaseID: "kb"})
	require.NoError(t, err)
	task := asynq.NewTask(types.TypeKnowledgePostProcess, body)
	require.NoError(t, svc.Handle(context.Background(), task))
	require.Empty(t, queue.taskTypes)
	require.Equal(t, types.ParseStatusCompleted, knowledge.ParseStatus)
	require.Equal(t, types.SummaryStatusNone, knowledge.SummaryStatus)
	// Re-delivery must not schedule Wiki recovery or any other work.
	require.NoError(t, svc.Handle(context.Background(), task))
	require.Empty(t, queue.taskTypes)
}

func TestManagedExistingEnrichmentTasksDoNotCallModels(t *testing.T) {
	fixture := newAutoTagFixture(t, `{"matches":[{"index":1,"confidence":0.9}]}`)
	fixture.repo.knowledge.ManagedWorkID = "work"
	require.NoError(t, fixture.handle(t))
	require.Empty(t, fixture.chatModel.messages)
	require.Empty(t, fixture.repo.added)

	knowledge := summaryKnowledge()
	knowledge.ManagedWorkID = "work"
	repo := &summaryColumnsRepo{t: t, knowledge: knowledge}
	svc := &knowledgeService{repo: repo, kbService: &reparseFailureKBService{kb: summaryKB()}, chunkService: &wikiEnqueueFailureChunkService{}}
	require.NoError(t, svc.ProcessSummaryGeneration(context.Background(), summaryGenerationTask(t)))
	require.Empty(t, repo.writes)
}

type managedGuardChunkRepo struct{ interfaces.ChunkRepository }

func (managedGuardChunkRepo) GetChunkByID(context.Context, uint64, string) (*types.Chunk, error) {
	return &types.Chunk{ID: "chunk", TenantID: 1, KnowledgeID: "k-1", KnowledgeBaseID: "kb-1", Content: "secret"}, nil
}

func TestManagedExistingQuestionAndGraphTasksAreBlocked(t *testing.T) {
	knowledge := summaryKnowledge()
	knowledge.ManagedWorkID = "work"
	repo := &summaryColumnsRepo{t: t, knowledge: knowledge}
	svc := &knowledgeService{repo: repo}
	for _, payload := range []types.QuestionGenerationPayload{
		{TenantID: 1, KnowledgeID: "k-1", KnowledgeBaseID: "kb-1"},
		{TenantID: 1, KnowledgeID: "k-1", KnowledgeBaseID: "kb-1", ChunkID: "chunk"},
	} {
		body, err := json.Marshal(payload)
		require.NoError(t, err)
		require.NoError(t, svc.ProcessQuestionGeneration(context.Background(), asynq.NewTask(types.TypeQuestionGeneration, body)))
	}
	graph := &ChunkExtractService{knowledgeRepo: repo, chunkRepo: managedGuardChunkRepo{}}
	body, err := json.Marshal(types.ExtractChunkPayload{TenantID: 1, ChunkID: "chunk"})
	require.NoError(t, err)
	require.NoError(t, graph.Handle(context.Background(), asynq.NewTask(types.TypeChunkExtract, body)))
}
