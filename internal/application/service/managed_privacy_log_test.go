package service

import (
	"bytes"
	"context"
	"testing"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type privacyDocReader struct{}

func (privacyDocReader) Read(context.Context, *types.ReadRequest) (*types.ReadResult, error) {
	return &types.ReadResult{}, nil
}

func TestDocumentLogsKeepNativeDetailsAndRedactManagedContent(t *testing.T) {
	logs := &bytes.Buffer{}
	log := logrus.New()
	log.SetOutput(logs)
	log.SetLevel(logrus.DebugLevel)
	native := context.WithValue(context.Background(), types.LoggerContextKey, logrus.NewEntry(log))
	managed := api.WithManagedJSON(native, func(context.Context, string, string, []byte) ([]byte, error) { return nil, nil })
	logDocumentTask(managed, "knowledge-managed", "/private/managed-file.txt", 1, 3)
	logDocumentChunkPreview(managed, 0, "中文秘密材料")
	managedRef := context.WithValue(managed, managedReferenceKey{}, managedcapability.Binding{EmbeddingModel: managedcapability.EmbeddingModel, EmbeddingSpace: managedcapability.EmbeddingSpace, WorkID: "work"})
	logReferencePath(managedRef, "/private/managed-file.txt", "")
	logReferencePath(managedRef, "/private/managed-file.txt", "knowledge-managed")
	_, err := (&knowledgeService{}).callDocReaderWithTimeout(managed, privacyDocReader{}, &types.ReadRequest{FileName: "managed-file.txt"})
	require.NoError(t, err)
	require.Contains(t, logs.String(), "knowledge-managed")
	require.NotContains(t, logs.String(), "/private/managed-file.txt")
	require.NotContains(t, logs.String(), "managed-file.txt")
	require.NotContains(t, logs.String(), "中文秘密材料")

	logs.Reset()
	logDocumentTask(native, "knowledge-native", "/private/native-file.txt", 1, 3)
	logDocumentChunkPreview(native, 0, "原生文档内容")
	logReferencePath(native, "/private/native-file.txt", "")
	logReferencePath(native, "/private/native-file.txt", "knowledge-native")
	_, err = (&knowledgeService{}).callDocReaderWithTimeout(native, privacyDocReader{}, &types.ReadRequest{FileName: "native-file.txt"})
	require.NoError(t, err)
	require.Contains(t, logs.String(), "knowledge-native")
	require.Contains(t, logs.String(), "/private/native-file.txt")
	require.Contains(t, logs.String(), "原生文档内容")
}
