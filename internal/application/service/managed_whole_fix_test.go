package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Tencent/WeKnora/internal/application/repository"
	sqliteRepo "github.com/Tencent/WeKnora/internal/application/repository/retriever/sqlite"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"math"
	"strings"
	"testing"
	"time"
)

func TestManagedWholeFixRejectsInt8Vec0(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	expected, e := managedVector(f.raw)
	require.NoError(t, e)
	require.NoError(t, f.db.Exec("DROP TABLE vec_embeddings_1024").Error)
	require.NoError(t, f.db.Exec("CREATE VIRTUAL TABLE vec_embeddings_1024 USING vec0(embedding int8[4096])").Error)
	sqlDB, e := f.db.DB()
	require.NoError(t, e)
	_, e = sqlDB.Exec("INSERT INTO vec_embeddings_1024(rowid,embedding) SELECT id,vec_int8(?) FROM lite_embeddings", expected)
	require.NoError(t, e)
	require.Error(t, f.finalize(), "wrong vec0 element type must fail before ready")
}
func TestManagedWholeFixNativeRetrieverExcludesManagedBeforeLogging(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	var logs bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logs)
	l.SetLevel(logrus.DebugLevel)
	ctx := context.WithValue(context.Background(), types.LoggerContextKey, logrus.NewEntry(l))
	repo := sqliteRepo.NewSQLiteRetrieveEngineRepository(f.db)
	res, e := repo.Retrieve(ctx, types.RetrieveParams{Query: strings.Repeat("a", 300), KnowledgeBaseIDs: []string{"kb"}, RetrieverType: types.KeywordsRetrieverType, TopK: 5})
	require.NoError(t, e)
	require.Len(t, res, 1)
	require.Empty(t, res[0].Results)
	require.NotContains(t, logs.String(), "content_preview=fixture.txt")
}
func TestManagedWholeFixProfileAndFallbackExcludeManagedMetadata(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	for _, sql := range []string{"ALTER TABLE knowledges ADD COLUMN file_type TEXT", "ALTER TABLE knowledges ADD COLUMN folder_path TEXT", "ALTER TABLE knowledges ADD COLUMN created_at DATETIME", "ALTER TABLE knowledges ADD COLUMN profile TEXT"} {
		require.NoError(t, f.db.Exec(sql).Error)
	}
	require.NoError(t, f.db.Exec("UPDATE knowledges SET title='PRIVATE-MANAGED-TITLE',file_name='PRIVATE-MANAGED-TITLE.txt',created_at=?,file_type='txt'", time.Now()).Error)
	require.NoError(t, f.db.Exec("INSERT INTO knowledges(id,tenant_id,knowledge_base_id,parse_status,enable_status,title,file_name,created_at,file_type) VALUES('native-profile',1,'kb','completed','enabled','NATIVE-PROFILE-TITLE','native.txt',?,'txt')", time.Now()).Error)
	repo := repository.NewKnowledgeRepository(f.db)
	rows, e := repo.ListKnowledgeProfileRows(context.Background(), 1, "kb")
	require.NoError(t, e)
	require.Len(t, rows, 1)
	require.Equal(t, "NATIVE-PROFILE-TITLE", rows[0].Title)
	pf := newKBProfileFixture(`{"gist":"native description","topics":[],"typical_questions":[]}`)
	pf.kb.TenantID = 1
	pf.docRepo.rows = rows
	_, e = pf.service.GenerateKnowledgeBaseProfile(context.Background(), pf.kb, true)
	require.NoError(t, e)
	require.Equal(t, 1, pf.chatModel.calls)
	svc := &sessionService{knowledgeService: &knowledgeService{repo: repo}}
	cm := &types.ChatManage{}
	cm.KnowledgeBaseIDs = []string{"kb"}
	listing := svc.buildKBDocumentListing(context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1)), cm)
	require.NotContains(t, listing, "PRIVATE-MANAGED-TITLE")
	require.Contains(t, listing, "NATIVE-PROFILE-TITLE")
}

type wholeFixReadRepo struct {
	interfaces.KnowledgeRepository
	rows []*types.Knowledge
}

func (r *wholeFixReadRepo) GetKnowledgeBatch(context.Context, uint64, []string) ([]*types.Knowledge, error) {
	return r.rows, nil
}

func (r *wholeFixReadRepo) ListKnowledgeByKnowledgeBaseID(context.Context, uint64, string) ([]*types.Knowledge, error) {
	return r.rows, nil
}

func TestManagedWholeFixOrdinaryBatchHidesButCleanupRetainsManagedRows(t *testing.T) {
	native := &types.Knowledge{ID: "native", KnowledgeBaseID: "kb"}
	managed := &types.Knowledge{ID: "managed", KnowledgeBaseID: "kb", ManagedWorkID: "work"}
	repo := &wholeFixReadRepo{rows: []*types.Knowledge{native, managed}}
	svc := &knowledgeService{repo: repo}
	batch, err := svc.GetKnowledgeBatch(context.Background(), 1, []string{native.ID, managed.ID})
	require.NoError(t, err)
	require.Equal(t, []*types.Knowledge{native}, batch)

	ctx := context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1))
	cleanup, err := svc.ListKnowledgeForCleanup(ctx, "kb")
	require.NoError(t, err)
	require.Equal(t, []*types.Knowledge{native, managed}, cleanup)
}

func TestManagedWholeFixRerankScoreValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want float64
		bad  bool
	}{
		{name: "zero", json: `{"output":{"results":[{"index":0,"relevance_score":0}]}}`, want: 0},
		{name: "one", json: `{"output":{"results":[{"index":0,"relevance_score":1}]}}`, want: 1},
		{name: "negative", json: `{"output":{"results":[{"index":0,"relevance_score":-0.01}]}}`, bad: true},
		{name: "above_one", json: `{"output":{"results":[{"index":0,"relevance_score":1.01}]}}`, bad: true},
		{name: "duplicate_score", json: `{"output":{"results":[{"index":0,"relevance_score":0.1,"relevance_score":0.9}]}}`, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := managedRerankScore([]byte(tc.json))
			if tc.bad {
				require.ErrorIs(t, err, ErrManagedWorkerUnavailable)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestManagedWholeFixReadyFlagWaitsForCompletion(t *testing.T) {
	k := &types.Knowledge{ManagedWorkID: "work", EnableStatus: "disabled"}
	finalizeIndexedKnowledgeState(k, 4096, 1, false, time.Now())
	require.Equal(t, "disabled", k.EnableStatus)
	require.Equal(t, types.ParseStatusProcessing, k.ParseStatus)
}

type wholeFixManualRepo struct {
	interfaces.KnowledgeRepository
	knowledge *types.Knowledge
	writes    int
}

func (r *wholeFixManualRepo) GetKnowledgeByID(context.Context, uint64, string) (*types.Knowledge, error) {
	return r.knowledge, nil
}
func (r *wholeFixManualRepo) UpdateKnowledge(context.Context, *types.Knowledge) error {
	r.writes++
	return errors.New("review-stop-at-first-unauthorized-write")
}
func TestManagedWholeFixNativeManualTaskRejectsManagedWithoutAuthority(t *testing.T) {
	k := &types.Knowledge{ID: "doc", TenantID: 1, KnowledgeBaseID: "kb", ManagedWorkID: "work", Type: "file", ParseStatus: types.ParseStatusPending}
	repo := &wholeFixManualRepo{knowledge: k}
	svc := &knowledgeService{repo: repo, tenantRepo: &summaryRefreshTenantRepo{tenant: &types.Tenant{ID: 1}}, kbService: &reparseFailureKBService{kb: &types.KnowledgeBase{ID: "kb", TenantID: 1}}}
	raw, e := json.Marshal(types.ManualProcessPayload{TenantID: 1, KnowledgeID: "doc", KnowledgeBaseID: "kb", Content: "unapproved replacement", NeedCleanup: true})
	require.NoError(t, e)
	e = svc.ProcessManualUpdate(context.Background(), asynq.NewTask(types.TypeManualProcess, raw))
	require.ErrorIs(t, e, ErrManagedWorkerUnavailable)
	require.Zero(t, repo.writes)
	require.Equal(t, types.ParseStatusPending, k.ParseStatus)
}

func TestManagedWholeFixManualStatesAndNativePositive(t *testing.T) {
	for _, state := range []string{types.ParseStatusPending, types.ParseStatusProcessing, types.ParseStatusFailed} {
		t.Run(state, func(t *testing.T) {
			for _, managed := range []bool{false, true} {
				k := &types.Knowledge{ID: "doc", TenantID: 1, KnowledgeBaseID: "kb", Type: "file", ParseStatus: state}
				if managed {
					k.ManagedWorkID = "work"
				}
				repo := &wholeFixManualRepo{knowledge: k}
				svc := &knowledgeService{repo: repo, tenantRepo: &summaryRefreshTenantRepo{tenant: &types.Tenant{ID: 1}}, kbService: &reparseFailureKBService{kb: &types.KnowledgeBase{ID: "kb", TenantID: 1}}}
				raw, err := json.Marshal(types.ManualProcessPayload{TenantID: 1, KnowledgeID: "doc", KnowledgeBaseID: "kb", Content: "replacement", NeedCleanup: true})
				require.NoError(t, err)
				err = svc.ProcessManualUpdate(context.Background(), asynq.NewTask(types.TypeManualProcess, raw))
				if managed {
					require.ErrorIs(t, err, ErrManagedWorkerUnavailable)
					require.Zero(t, repo.writes)
					require.Equal(t, state, k.ParseStatus)
				} else {
					require.ErrorContains(t, err, "review-stop-at-first-unauthorized-write")
					require.Equal(t, 1, repo.writes, "native manual processing retains its write path")
				}
			}
		})
	}
}

func TestManagedWholeFixVec0ShapeAndMetricBeforeAndAfterReady(t *testing.T) {
	for _, mode := range []string{"int8", "wrong_dimension", "l2", "default_metric"} {
		for _, ready := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ready=%t", mode, ready), func(t *testing.T) {
				f := newCompletionFixture(t)
				f.ingest()
				if ready {
					require.NoError(t, f.finalize())
				}
				expected, err := managedVector(f.raw)
				require.NoError(t, err)
				require.NoError(t, f.db.Exec("DROP TABLE vec_embeddings_1024").Error)
				column, vector := "float[1024] distance_metric=l2", expected
				switch mode {
				case "int8":
					column = "int8[4096]"
				case "wrong_dimension":
					column, vector = "float[512] distance_metric=cosine", expected[:2048]
				case "default_metric":
					column = "float[1024]"
				}
				require.NoError(t, f.db.Exec("CREATE VIRTUAL TABLE vec_embeddings_1024 USING vec0(embedding "+column+")").Error)
				if mode == "int8" {
					var rowID int64
					require.NoError(t, f.db.Raw("SELECT id FROM lite_embeddings LIMIT 1").Scan(&rowID).Error)
					sqlDB, dbErr := f.db.DB()
					require.NoError(t, dbErr)
					_, dbErr = sqlDB.Exec("INSERT INTO vec_embeddings_1024(rowid,embedding) VALUES(?,vec_int8(?))", rowID, vector)
					require.NoError(t, dbErr)
				} else {
					require.NoError(t, f.db.Exec("INSERT INTO vec_embeddings_1024(rowid,embedding) SELECT id,? FROM lite_embeddings", vector).Error)
				}
				if ready {
					_, err = f.status("completed-index-use-v1", f.use())
					require.Error(t, err)
				} else {
					require.Error(t, f.finalize())
					var n int64
					require.NoError(t, f.db.Model(&managedCompletion{}).Count(&n).Error)
					require.Zero(t, n)
				}
			})
		}
	}
}

func TestManagedWholeFixOrdinaryRecallKeepsNativeTopKAndLogs(t *testing.T) {
	f := newCompletionFixture(t)
	f.ingest()
	require.NoError(t, f.finalize())
	require.NoError(t, f.db.Exec("INSERT INTO knowledges(id,tenant_id,knowledge_base_id,parse_status,enable_status,title) VALUES('native',1,'kb','completed','enabled','native title')").Error)
	expected, err := managedVector(f.raw)
	require.NoError(t, err)
	vector := make([]float32, 1024)
	for i := range vector {
		vector[i] = math.Float32frombits(binary.LittleEndian.Uint32(expected[i*4:]))
	}
	native := append([]float32(nil), vector...)
	native[0] += 0.01
	repo := sqliteRepo.NewSQLiteRetrieveEngineRepository(f.db)
	require.NoError(t, repo.BatchSave(context.Background(), []*types.IndexInfo{{SourceID: "native-chunk", SourceType: types.ChunkSourceType, ChunkID: "native-chunk", KnowledgeID: "native", KnowledgeBaseID: "kb", IsEnabled: true, Content: strings.Repeat("a", 300) + " NATIVE-VISIBLE"}}, map[string]any{"embedding": map[string][]float32{"native-chunk": native}}))
	for _, branch := range []types.RetrieverType{types.KeywordsRetrieverType, types.VectorRetrieverType} {
		var logs bytes.Buffer
		l := logrus.New()
		l.SetOutput(&logs)
		l.SetLevel(logrus.DebugLevel)
		ctx := context.WithValue(context.Background(), types.LoggerContextKey, logrus.NewEntry(l))
		results, err := repo.Retrieve(ctx, types.RetrieveParams{Query: strings.Repeat("a", 300), Embedding: vector, KnowledgeBaseIDs: []string{"kb"}, RetrieverType: branch, TopK: 1})
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Len(t, results[0].Results, 1)
		require.Equal(t, "native", results[0].Results[0].KnowledgeID)
		require.Contains(t, logs.String(), "chunk_id=native-chunk")
		require.NotContains(t, logs.String(), "fixture.txt")
		require.NotContains(t, logs.String(), "chunk_id=chunk,")
	}
}
