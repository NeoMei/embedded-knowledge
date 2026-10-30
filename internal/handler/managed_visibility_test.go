package handler

import (
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestOrdinaryKnowledgeResultsHideManaged(t *testing.T) {
	rows := []*types.Knowledge{{ID: "native"}, {ID: "managed", ManagedWorkID: "work"}, nil}
	visible := ordinaryKnowledgeRows(rows)
	require.Len(t, visible, 1)
	require.Equal(t, "native", visible[0].ID)
}
