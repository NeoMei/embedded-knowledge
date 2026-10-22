package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	secutils "github.com/Tencent/WeKnora/internal/utils"
	"github.com/stretchr/testify/require"
)

type refKnowledgeRepoStub struct {
	interfaces.KnowledgeRepository

	existing    *types.Knowledge
	created     *types.Knowledge
	createCalls int
}

func (r *refKnowledgeRepoStub) GetKnowledgeByFilePath(
	ctx context.Context,
	tenantID uint64,
	kbID string,
	filePath string,
) (*types.Knowledge, error) {
	return r.existing, nil
}

func (r *refKnowledgeRepoStub) CreateKnowledge(ctx context.Context, knowledge *types.Knowledge) error {
	r.createCalls++
	copied := *knowledge
	r.created = &copied
	return nil
}

func (r *refKnowledgeRepoStub) GetKnowledgeTags(
	ctx context.Context,
	knowledgeIDs []string,
) (map[string][]*types.KnowledgeTag, error) {
	return map[string][]*types.KnowledgeTag{}, nil
}

func newReferenceService(repo *refKnowledgeRepoStub, task *createKnowledgeTaskEnqueuerStub) *knowledgeService {
	return &knowledgeService{
		repo:      repo,
		kbService: &createKnowledgeFileKBServiceStub{kb: &types.KnowledgeBase{ID: "kb-1"}},
		// The global storage service stands in for the tenant's engine, which a
		// reference ingest still needs for assets extracted during parsing.
		fileSvc: &createKnowledgeFileServiceStub{},
		task:    task,
	}
}

func TestCreateKnowledgeFromPathRegistersInPlaceAndEnqueuesParse(t *testing.T) {
	t.Parallel()

	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "meeting.md")
	require.NoError(t, os.WriteFile(sourcePath, []byte("# notes"), 0o644))

	repo := &refKnowledgeRepoStub{}
	task := &createKnowledgeTaskEnqueuerStub{}
	svc := newReferenceService(repo, task)

	knowledge, err := svc.CreateKnowledgeFromPath(
		newCreateKnowledgeFileContext(), "kb-1", sourcePath, "", "proj/docs", nil, nil, "", nil,
	)
	require.NoError(t, err)
	require.NotNil(t, knowledge)
	require.Equal(t, secutils.ReferenceFilePath(sourcePath), knowledge.FilePath)
	require.Equal(t, "meeting.md", knowledge.FileName)
	require.Equal(t, "proj/docs", knowledge.FolderPath)
	require.Equal(t, int64(len("# notes")), knowledge.FileSize)
	require.NotEmpty(t, knowledge.FileHash)
	require.Equal(t, 1, repo.createCalls)
	require.Equal(t, 1, task.calls, "registration must hand the document to the parse queue")
}

func TestCreateKnowledgeFromPathIsIdempotentPerPath(t *testing.T) {
	t.Parallel()

	repo := &refKnowledgeRepoStub{existing: &types.Knowledge{ID: "k-1", FileName: "meeting.md"}}
	task := &createKnowledgeTaskEnqueuerStub{}
	svc := newReferenceService(repo, task)
	sourcePath := filepath.Join(t.TempDir(), "meeting.md")
	require.NoError(t, os.WriteFile(sourcePath, []byte("# notes"), 0o644))

	knowledge, err := svc.CreateKnowledgeFromPath(
		newCreateKnowledgeFileContext(), "kb-1", sourcePath, "", "", nil, nil, "", nil,
	)
	require.NoError(t, err)
	require.Equal(t, "k-1", knowledge.ID)
	require.Zero(t, repo.createCalls, "a known path must not be registered twice")
	require.Zero(t, task.calls, "a known path must not be parsed again")
}

func TestCreateKnowledgeFromPathRejectsRelativePath(t *testing.T) {
	t.Parallel()

	svc := newReferenceService(&refKnowledgeRepoStub{}, &createKnowledgeTaskEnqueuerStub{})
	_, err := svc.CreateKnowledgeFromPath(
		newCreateKnowledgeFileContext(), "kb-1", "docs/meeting.md", "", "", nil, nil, "", nil,
	)
	require.Error(t, err)
}
