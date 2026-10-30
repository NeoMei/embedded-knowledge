package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
)

func TestManagedReferenceCannotBeReadThroughOrdinaryPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meeting.md")
	require.NoError(t, os.WriteFile(path, []byte("notes"), 0600))
	repo := &refKnowledgeRepoStub{existing: &types.Knowledge{ID: "managed", ManagedWorkID: "work"}}
	task := &createKnowledgeTaskEnqueuerStub{}
	got, err := newReferenceService(repo, task).CreateKnowledgeFromPath(newCreateKnowledgeFileContext(), "kb-1", path, "", "", nil, nil, "", nil)
	require.ErrorIs(t, err, ErrManagedWorkerUnavailable)
	require.Nil(t, got)
	require.Zero(t, task.calls)
	require.Zero(t, repo.createCalls)
}

func TestManagedMixedMutationRejectedBeforeChanges(t *testing.T) {
	for _, operation := range []string{"folder", "tag", "delete", "reparse"} {
		t.Run(operation, func(t *testing.T) {
			f := newDocumentWriteFixture(t)
			require.NoError(t, f.db.Create(&types.Knowledge{ID: "managed", TenantID: 7, KnowledgeBaseID: "kb", ManagedWorkID: "work", ParseStatus: types.ParseStatusCompleted}).Error)
			var err error
			switch operation {
			case "folder":
				_, err = f.svc.MoveKnowledgeToFolder(f.ctx, "kb", []string{"doc", "managed"}, "destination")
			case "tag":
				err = f.svc.UpdateKnowledgeTagBatch(f.ctx, "kb", map[string][]string{"doc": {}, "managed": {}})
			case "delete":
				err = f.svc.DeleteKnowledgeList(f.ctx, []string{"doc", "managed"})
			case "reparse":
				_, _, err = f.svc.reparseTaskScope(context.Background(), types.KnowledgeListReparsePayload{TenantID: 7, KnowledgeBaseID: "kb", KnowledgeIDs: []string{"doc", "managed"}})
			}
			require.Error(t, err)
			f.requireNoWrites(t)
			var row types.Knowledge
			require.NoError(t, f.db.First(&row, "id = ?", "doc").Error)
			require.Equal(t, types.ManualKnowledgeStatusDraft, row.ParseStatus)
			require.Empty(t, row.FolderPath)
		})
	}
}
