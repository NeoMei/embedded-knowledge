package service

import (
	"context"
	"testing"

	"github.com/Tencent/WeKnora/internal/application/access"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
)

func TestManagedKnowledgeCannotBeCopiedMovedOrDownloadedNatively(t *testing.T) {
	for _, op := range []access.KBTransferOperation{access.KBTransferClone, access.KBTransferMove} {
		t.Run(string(op), func(t *testing.T) {
			f := transferFixture(t, op)
			before, err := f.repo.ListKnowledgeByKnowledgeBaseID(f.ctx, 7, "other")
			require.NoError(t, err)
			require.NoError(t, f.db.Model(&types.Knowledge{}).Where("id = ?", "doc").Update("managed_work_id", "managed-work").Error)
			if op == access.KBTransferClone {
				require.Error(t, f.svc.executeKnowledgeClone(f.ctx, f.kbs.values["kb"], f.kbs.values["other"], nil))
			} else {
				require.Error(t, f.svc.ProcessKnowledgeMove(context.Background(), moveTask(t, []string{"doc"}, "reuse_vectors")))
			}
			rows, err := f.repo.ListKnowledgeByKnowledgeBaseID(f.ctx, 7, "other")
			require.NoError(t, err)
			require.Len(t, rows, len(before))
			row, err := f.repo.GetKnowledgeByID(f.ctx, 7, "doc")
			require.NoError(t, err)
			require.Equal(t, "kb", row.KnowledgeBaseID)
			require.Equal(t, types.ParseStatusCompleted, row.ParseStatus)
			ctx := context.WithValue(f.ctx, types.TenantIDContextKey, uint64(7))
			_, _, err = f.svc.GetKnowledgeFile(ctx, "doc")
			require.Error(t, err)
		})
	}
}
