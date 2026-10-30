package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	"github.com/stretchr/testify/require"
)

type kbDeleteStatusRepo struct {
	interfaces.KnowledgeBaseRepository
	deleted bool
	err     error
}

func (r kbDeleteStatusRepo) IsSoftDeleted(context.Context, uint64, string) (bool, error) {
	return r.deleted, r.err
}

type kbDeleteGuardRepo struct {
	interfaces.KnowledgeRepository
	items []*types.Knowledge
	err   error
}

func (r *kbDeleteGuardRepo) ListKnowledgeByKnowledgeBaseID(context.Context, uint64, string) ([]*types.Knowledge, error) {
	return r.items, r.err
}

func TestManagedKnowledgeProtectsWholeKBFromDeleteAndQueuedCleanup(t *testing.T) {
	const kbID = "kb"
	kbRepo := &kbDeleteKBRepo{fakeKBRepo: *newFakeKBRepo()}
	kbRepo.rows[kbID] = &types.KnowledgeBase{ID: kbID, TenantID: 1}
	items := &kbDeleteGuardRepo{items: []*types.Knowledge{{ID: "native"}, {ID: "managed", ManagedWorkID: "work"}}}
	inspector := &recordingKBTaskInspector{repo: kbRepo}
	enqueue := &recordingKBDeleteEnqueuer{}
	wiki := &recordingWikiRepo{}
	svc := &knowledgeBaseService{repo: kbRepo, kgRepo: items, asynqClient: enqueue, taskInspector: inspector, wikiRepo: wiki}
	err := svc.DeleteKnowledgeBase(ctxWithTenantStorage(1, "local"), kbID)
	require.Error(t, err)
	require.Empty(t, kbRepo.deletedID)
	require.Zero(t, enqueue.calls)
	require.Empty(t, inspector.calls)
	svc.repo = kbDeleteStatusRepo{deleted: true}
	err = svc.ProcessKBDelete(context.Background(), kbDeletePayload(t, kbID, 1))
	require.Error(t, err)
	require.Empty(t, wiki.pagesCalls)
	require.Empty(t, wiki.foldersCalls)
	require.Empty(t, wiki.revisionsCalls)
	require.Empty(t, wiki.issuesCalls)
	require.Empty(t, inspector.calls)
}

func TestKBDeleteDoesNotProceedWhenKnowledgeLookupUnavailable(t *testing.T) {
	const kbID = "kb"
	kbRepo := &kbDeleteKBRepo{fakeKBRepo: *newFakeKBRepo()}
	kbRepo.rows[kbID] = &types.KnowledgeBase{ID: kbID, TenantID: 1}
	lookupErr := errors.New("database unavailable")
	items := &kbDeleteGuardRepo{err: lookupErr}
	wiki := &recordingWikiRepo{}
	svc := &knowledgeBaseService{repo: kbRepo, kgRepo: items, wikiRepo: wiki}
	require.ErrorIs(t, svc.DeleteKnowledgeBase(ctxWithTenantStorage(1, "local"), kbID), lookupErr)
	require.Empty(t, kbRepo.deletedID)
	svc.repo = kbDeleteStatusRepo{deleted: true}
	require.ErrorIs(t, svc.ProcessKBDelete(context.Background(), kbDeletePayload(t, kbID, 1)), lookupErr)
	require.Empty(t, wiki.pagesCalls)
}

func TestOldKBDeleteTaskCannotCleanLiveOrUnknownKB(t *testing.T) {
	for _, tc := range []struct {
		deleted bool
		err     error
	}{{false, nil}, {false, errors.New("database down")}} {
		wiki := &recordingWikiRepo{}
		inspector := &recordingKBTaskInspector{}
		svc := &knowledgeBaseService{repo: kbDeleteStatusRepo{deleted: tc.deleted, err: tc.err}, kgRepo: emptyKBKnowledgeRepo{}, wikiRepo: wiki, taskInspector: inspector}
		require.Error(t, svc.ProcessKBDelete(context.Background(), kbDeletePayload(t, "kb", 1)))
		require.Empty(t, wiki.pagesCalls)
		require.Empty(t, inspector.calls)
	}
}
