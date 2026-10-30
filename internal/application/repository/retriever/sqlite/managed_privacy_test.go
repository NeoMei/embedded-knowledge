package sqlite

import (
	"bytes"
	"context"
	"testing"

	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedRetrievalDoesNotLogQueryOrContent(t *testing.T) {
	repo := newSQLiteRetrieverTestRepository(t)
	item := sqliteTestIndex("chunk", "kb", "document", "", true)
	item.Content = "privatecontentsentinel"
	saveSQLiteTestVector(t, repo, item, []float32{1, 0})
	var output bytes.Buffer
	log := logrus.New()
	log.SetOutput(&output)
	log.SetLevel(logrus.DebugLevel)
	ctx := context.WithValue(context.Background(), types.LoggerContextKey, logrus.NewEntry(log))
	managed := api.WithManagedJSON(ctx, func(context.Context, string, string, []byte) ([]byte, error) { return nil, nil })
	params := types.RetrieveParams{Embedding: []float32{1, 0}, TopK: 1}
	result, err := repo.vectorRetrieve(managed, params)
	require.NoError(t, err)
	require.Len(t, result[0].Results, 1)
	assert.NotContains(t, output.String(), item.Content)
	if repo.db.Migrator().HasTable("lite_embeddings_fts") {
		_, err = repo.keywordsRetrieve(managed, types.RetrieveParams{Query: item.Content, TopK: 1})
		require.NoError(t, err)
		assert.NotContains(t, output.String(), item.Content)
	}
	output.Reset()
	_, err = repo.vectorRetrieve(ctx, params)
	require.NoError(t, err)
	assert.Contains(t, output.String(), item.Content, "ordinary logging remains unchanged")
}
