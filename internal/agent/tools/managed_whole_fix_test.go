package tools

import (
	"context"
	"encoding/json"
	"testing"
)

func TestManagedWholeFixOrdinaryReadDocumentRejectsManagedChunks(t *testing.T) {
	tool, _ := newReadDocumentFixture(1)
	docs := tool.knowledgeService.(*readDocKnowledgeService)
	docs.docs["doc-1"].ManagedWorkID = "managed-work"
	docs.docs["doc-1"].FileType = "txt"
	result, e := tool.Execute(context.Background(), json.RawMessage(`{"id":"doc-1"}`))
	if e == nil || result == nil || result.Success {
		t.Fatalf("managed document must be refused: %v %+v", e, result)
	}
}
