package service

import (
	"context"
	"testing"

	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	"github.com/stretchr/testify/require"
)

type managedParserRemote struct {
	interfaces.DocumentReader
	calls int
}

func (f *managedParserRemote) Read(_ context.Context, _ *types.ReadRequest) (*types.ReadResult, error) {
	f.calls++
	return &types.ReadResult{MarkdownContent: "remote"}, nil
}

type managedParserTenant struct{ interfaces.TenantService }

func TestManagedTextParserNeverUsesConfiguredRemote(t *testing.T) {
	remote := &managedParserRemote{}
	s := &knowledgeService{documentReader: remote, tenantService: &managedParserTenant{}}
	native := context.Background()
	managed := api.WithManagedJSON(native, func(context.Context, string, string, []byte) ([]byte, error) { return nil, nil })
	for _, engine := range []string{"", "simple", "builtin", "unknown-remote", "mineru_cloud"} {
		reader := s.resolveDocReader(managed, engine, "txt", false, nil)
		require.NotNil(t, reader, engine)
		result, err := reader.Read(managed, &types.ReadRequest{FileName: "test.txt", FileType: "txt", FileContent: []byte("中文内容")})
		require.NoError(t, err, engine)
		require.Contains(t, result.MarkdownContent, "中文内容", engine)
		require.Zero(t, remote.calls, engine)
	}
	require.Nil(t, s.resolveDocReader(managed, "builtin", "pdf", false, nil))
	reader := s.resolveDocReader(native, "builtin", "txt", false, nil)
	require.NotNil(t, reader)
	_, err := reader.Read(native, &types.ReadRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, remote.calls, "native parser selection stays unchanged")
}
