package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/infrastructure/chunker"
	"github.com/Tencent/WeKnora/internal/infrastructure/docparser"
	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const approvedTXTFileSHA256 = "646f1958415b538106574a3ad57fcfc3dad30c93f248387bf21845a739bb6c6b"

func approvedTXT(t *testing.T) []byte {
	t.Helper()
	path := os.Getenv("WEKNORA_APPROVED_TXT_FIXTURE")
	if path == "" {
		path = filepath.Join("testdata", "approved-300-byte-acceptance.txt")
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Len(t, raw, 300)
	require.Equal(t, approvedTXTFileSHA256, managedSHA(raw))
	require.NotEqual(t, string(raw), strings.TrimSpace(string(raw)))
	return raw
}

func TestApprovedTXTActualParserKeepsRawChunkAndTrimsOnlyEmbedding(t *testing.T) {
	raw := approvedTXT(t)
	parsed, err := (&docparser.SimpleFormatReader{}).Read(context.Background(), &types.ReadRequest{FileName: "acceptance.txt", FileType: "txt", FileContent: raw})
	require.NoError(t, err)
	chunks := chunker.Split(chunker.NormalizeLineEndings(parsed.MarkdownContent), chunker.DefaultConfig())
	require.Len(t, chunks, 1)
	require.Equal(t, string(raw), chunks[0].Content)
	chunk := types.Chunk{Content: chunks[0].Content, ContextHeader: chunks[0].ContextHeader}
	require.Equal(t, strings.TrimSpace(string(raw)), chunk.EmbeddingContent())
	require.Equal(t, "acceptance.txt\n"+strings.TrimSpace(string(raw)), buildKnowledgeIndexContent(&types.Knowledge{Title: "acceptance.txt"}, chunk.EmbeddingContent()))
}

func TestPilotDocumentWhitespaceKeepsOriginalBounds(t *testing.T) {
	for _, text := range []string{"plain", "\n plain text \n", "\u3000中文。\n", string(approvedTXT(t))} {
		require.True(t, pilotDocumentText([]byte(text)), "%q", text)
	}
	for _, raw := range [][]byte{nil, []byte(" \n\u3000"), []byte(strings.Repeat("a", 300) + "\n"), []byte("text#heading"), []byte("text\t"), []byte("text\r\n"), []byte("text\x00"), []byte("text🙂"), []byte("text\u00a0"), {0xff}} {
		require.False(t, pilotDocumentText(raw), "%q", raw)
	}
	require.False(t, pilotText([]byte(" query\n")), "query edge whitespace remains invalid")
}

func TestApprovedTXTRealSQLiteIngestCompletionAndSearch(t *testing.T) {
	f := newCompletionFixture(t)
	f.document = approvedTXT(t)
	f.ingest()
	require.NoError(t, f.finalize())
	reply, err := f.status("completed-index-discover-v1", f.discover())
	require.NoError(t, err)
	require.Equal(t, "ready", reply.Discovery.State)
	var producer managedProducerFacts
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
		var err error
		producer, err = f.worker.producerTx(tx, "work")
		return err
	}))
	require.Equal(t, approvedTXTFileSHA256, producer.SnapshotSHA256)
	use := f.use()
	f.search = managedcapability.SearchBinding{IndexBinding: f.binding.IndexBinding, CompletionDigest: use.CompletionDigest, IndexWorkID: "work", TenantID: 1, ActorID: "actor", AccountID: "payer", TaskID: "search-task", WorkID: "search-work", GrantID: "search-grant", KnowledgeBaseID: "kb", KnowledgeID: "doc", QueryDigest: strings.Repeat("a", 64), EmbeddingModel: f.binding.EmbeddingModel, EmbeddingSpace: f.binding.EmbeddingSpace, RerankModel: "qwen3-rerank"}
	now := f.now.Load()
	token := f.sign("weknora-search-v1", managedcapability.SearchClaims{Issuer: "issuer", Audience: "weknora", SearchBinding: f.search, IssuedAt: now, ExpiresAt: now + 30})
	svc := &knowledgeBaseService{managedWorker: f.worker, kgRepo: completionKnowledgeRepo{db: f.db}}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), types.TenantIDContextKey, uint64(1)), 5*time.Second)
	defer cancel()
	result, err := svc.ManagedHybridSearch(ctx, "kb", token)
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	require.Equal(t, string(f.document), result.Results[0].Content)
	require.EqualValues(t, 3, f.dispatches.Load(), "one ingest embedding, one query embedding and one raw-chunk rerank")
	_, err = svc.ManagedHybridSearch(ctx, "kb", token)
	require.NoError(t, err)
	require.EqualValues(t, 3, f.dispatches.Load(), "repeated work recovers settled results without another model call")
	f.denied.Store(true)
	_, err = svc.ManagedHybridSearch(ctx, "kb", token)
	require.Error(t, err)
	require.EqualValues(t, 3, f.dispatches.Load())
}

func TestApprovedTXTCompletionStillRejectsTrimmedChunkAndChangedEmbedding(t *testing.T) {
	for _, changed := range []string{"chunk", "embedding", "vector"} {
		t.Run(changed, func(t *testing.T) {
			f := newCompletionFixture(t)
			f.document = approvedTXT(t)
			f.ingest()
			switch changed {
			case "chunk":
				require.NoError(t, f.db.Exec("UPDATE chunks SET content=?", strings.TrimSpace(string(f.document))).Error)
			case "embedding":
				require.NoError(t, f.db.Exec("UPDATE lite_embeddings SET content=?", "fixture.txt\n"+string(f.document)).Error)
			case "vector":
				require.NoError(t, f.db.Exec("UPDATE vec_embeddings_1024 SET embedding=?", make([]byte, 4096)).Error)
			}
			require.Error(t, f.finalize())
			var completions int64
			require.NoError(t, f.db.Model(&managedCompletion{}).Count(&completions).Error)
			require.Zero(t, completions)
			require.EqualValues(t, 1, f.dispatches.Load(), "failed provenance checks never dispatch another model call")
		})
	}
}
