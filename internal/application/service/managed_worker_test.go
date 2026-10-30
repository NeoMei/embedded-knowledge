package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Tencent/WeKnora/internal/infrastructure/chunker"
	"github.com/Tencent/WeKnora/internal/infrastructure/docparser"
	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedDocumentTaskCannotFallBackToNativeWorker(t *testing.T) {
	payload := types.DocumentProcessPayload{TenantID: 1, KnowledgeBaseID: "kb", KnowledgeID: "doc", ManagedWorkID: "work"}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	svc := &knowledgeService{}
	err = svc.ProcessDocument(context.Background(), asynq.NewTask(types.TypeDocumentProcess, body))
	require.ErrorIs(t, err, ErrManagedWorkerUnavailable)
}

type deniedManagedWorker struct{}

func (deniedManagedWorker) Prepare(context.Context, types.DocumentProcessPayload) (*managedWorkerAdmission, error) {
	return nil, errors.New("authority unavailable")
}
func (deniedManagedWorker) Register(context.Context, uint64, string, string, string) (managedcapability.Binding, error) {
	return managedcapability.Binding{EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace, }, errors.New("authority unavailable")
}
func TestManagedDocumentStopsBeforeNativeDBOnRevokedAuthority(t *testing.T) {
	payload := types.DocumentProcessPayload{TenantID: 1, KnowledgeBaseID: "kb", KnowledgeID: "doc", ManagedWorkID: "work"}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	svc := &knowledgeService{managedWorker: deniedManagedWorker{}}
	err = svc.ProcessDocument(context.Background(), asynq.NewTask(types.TypeDocumentProcess, body))
	require.Error(t, err)
}

func TestManagedDocumentRecordRejectsPayloadWithoutWorkID(t *testing.T) {
	knowledge := processingKnowledge()
	knowledge.ManagedWorkID = "work"
	repo := &embedFailureKnowledgeRepo{knowledge: knowledge}
	svc := &knowledgeService{repo: repo, tenantRepo: &summaryRefreshTenantRepo{tenant: &types.Tenant{ID: 1}}}
	err := svc.ProcessDocument(context.Background(), newDocumentProcessTask(t, 1))
	require.ErrorIs(t, err, ErrManagedWorkerUnavailable)
	require.Empty(t, repo.updates)
}

type testManagedWorker struct{ binding managedcapability.Binding }

func (t testManagedWorker) Prepare(context.Context, types.DocumentProcessPayload) (*managedWorkerAdmission, error) {
	return nil, errors.New("not invoked")
}
func (t testManagedWorker) Register(context.Context, uint64, string, string, string) (managedcapability.Binding, error) {
	return t.binding, nil
}
func TestManagedReferenceCreatesBoundIDAndWorkerPayload(t *testing.T) {
	repo := &refKnowledgeRepoStub{}
	queue := &recordManagedQueue{}
	svc := newReferenceService(repo, &createKnowledgeTaskEnqueuerStub{})
	svc.task = queue
	binding := managedcapability.Binding{EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace, TenantID: 1, KnowledgeBaseID: "kb-1", KnowledgeID: "22ae397e-8e09-4567-8453-340f88a1bda6", WorkID: "work"}
	svc.managedWorker = testManagedWorker{binding: binding}
	file := filepath.Join(t.TempDir(), "synthetic.txt")
	require.NoError(t, os.WriteFile(file, []byte("synthetic"), 0600))
	knowledge, err := svc.CreateManagedKnowledgeFromPath(newCreateKnowledgeFileContext(), "kb-1", file, "capability")
	require.NoError(t, err)
	require.Equal(t, binding.KnowledgeID, knowledge.ID)
	require.Equal(t, "work", knowledge.ManagedWorkID)
	require.Equal(t, 1, queue.calls)
	var payload types.DocumentProcessPayload
	require.NoError(t, json.Unmarshal(queue.task.Payload(), &payload))
	require.Equal(t, "work", payload.ManagedWorkID)
	require.NotContains(t, string(queue.task.Payload()), "capability")
}

type recordManagedQueue struct {
	calls int
	task  *asynq.Task
}

func (q *recordManagedQueue) Enqueue(task *asynq.Task, _ ...asynq.Option) (*asynq.TaskInfo, error) {
	q.calls++
	q.task = task
	return &asynq.TaskInfo{}, nil
}

func TestPilotTxtParserAndChunkPlanMatchesHostContract(t *testing.T) {
	document := []byte(strings.Repeat("a", 300))
	require.Len(t, document, 300)
	result, err := (&docparser.SimpleFormatReader{}).Read(context.Background(), &types.ReadRequest{FileName: "fixture.txt", FileType: "txt", FileContent: document})
	require.NoError(t, err)
	chunks := chunker.Split(result.MarkdownContent, chunker.DefaultConfig())
	require.Len(t, chunks, 1)
	knowledge := &types.Knowledge{Title: "fixture.txt"}
	actual := buildKnowledgeIndexContent(knowledge, chunks[0].Content)
	require.Equal(t, "fixture.txt\n"+strings.TrimSpace(string(document)), actual)
}
