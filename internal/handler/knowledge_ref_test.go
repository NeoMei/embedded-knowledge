package handler

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagedReferenceRequestRejectsDuplicateFields(t *testing.T) {
	for _, raw := range []string{
		`{"path":"/safe","path":"/other","capability":"signed"}`,
		`{"path":"/safe","capability":"first","capability":"second"}`,
	} {
		_, err := decodeManagedReferenceRequest([]byte(raw))
		require.Error(t, err)
	}
	_, err := decodeManagedReferenceRequest([]byte(`{"path":"/safe","capability":"signed"}`))
	require.NoError(t, err)
}

func TestManagedCapabilityRequestRejectsDuplicateAndUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{"capability":"first","capability":"second"}`,
		`{"capability":"signed","extra":true}`,
		`{"capability":"signed"} {}`,
	} {
		_, err := decodeManagedCapabilityRequest([]byte(raw))
		require.Error(t, err)
	}
	got, err := decodeManagedCapabilityRequest([]byte(`{"capability":"signed"}`))
	require.NoError(t, err)
	require.Equal(t, "signed", got)
}
