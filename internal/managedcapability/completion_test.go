package managedcapability

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestCompletedProofStrictNestedJSON(t *testing.T) {
	for _, raw := range []string{`{"version":"x","version":"y"}`, `{"binding":{"actor_id":"a","actor_id":"b"}}`, `{"purpose":"completion_discover","surprise":true}`, `{"issued_at":1.5}`, `{} {}`} {
		var c CompletionDiscover
		require.Error(t, StrictJSON([]byte(raw), &c), raw)
	}
}
func TestCompletedProofFrozenFieldShapes(t *testing.T) {
	raw, err := os.ReadFile("testdata/completion-contract-v1.json")
	require.NoError(t, err)
	var all map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &all))
	var storage StorageRequest
	var discover CompletionDiscover
	var use CompletedUse
	require.NoError(t, StrictJSON(all["storage"], &storage))
	require.NoError(t, StrictJSON(all["discover"], &discover))
	require.NoError(t, StrictJSON(all["use"], &use))
	require.True(t, ValidIndexBinding(discover.Binding.IndexBinding))
	require.Equal(t, discover.Binding.NamespaceID, use.NamespaceID)
}
