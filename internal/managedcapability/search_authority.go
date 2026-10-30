package managedcapability

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

func (h *HostAuthority) searchPost(ctx context.Context, route string, request map[string]string) (string, []byte, error) {
	if h == nil || ctx == nil {
		return "", nil, ErrInvalid
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", nil, ErrInvalid
	}
	nonce := hex.EncodeToString(random[:])
	request["nonce"] = nonce
	raw, err := json.Marshal(request)
	if err != nil {
		return "", nil, ErrInvalid
	}
	base := strings.TrimSuffix(h.endpoint, "/knowledge-work/authorize")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/knowledge-search/"+route, bytes.NewReader(raw))
	if err != nil {
		return "", nil, ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := h.do(req, raw)
	if err != nil {
		return "", nil, ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 24<<20))
	if err != nil || len(data) >= 24<<20 {
		return "", nil, ErrInvalid
	}
	return nonce, data, nil
}
func (h *HostAuthority) SearchCheck(ctx context.Context, b SearchBinding) error {
	nonce, raw, err := h.searchPost(ctx, "authorize", map[string]string{"work_id": b.WorkID})
	if err != nil {
		return ErrInvalid
	}
	var result struct {
		Assertion string `json:"assertion"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return ErrInvalid
	}
	_, err = h.verifier.VerifySearchActive(result.Assertion, b, nonce)
	return err
}
func (h *HostAuthority) SearchSnapshot(ctx context.Context, b SearchBinding) ([]byte, error) {
	nonce, raw, err := h.searchPost(ctx, "snapshot", map[string]string{"work_id": b.WorkID})
	if err != nil {
		return nil, ErrInvalid
	}
	var result struct {
		Assertion string `json:"assertion"`
		Content   string `json:"content"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return nil, ErrInvalid
	}
	body, err := base64.StdEncoding.DecodeString(result.Content)
	if err != nil || base64.StdEncoding.EncodeToString(body) != result.Content {
		return nil, ErrInvalid
	}
	if _, err = h.verifier.VerifySearchSnapshot(result.Assertion, b, nonce, body); err != nil {
		return nil, ErrInvalid
	}
	return body, nil
}
func (h *HostAuthority) SearchResult(ctx context.Context, b SearchBinding, callID, operation string) ([]byte, error) {
	model, wire := b.EmbeddingModel, "embeddings.create"
	if operation == "rerank" {
		model, wire = b.RerankModel, "rerank.create"
	} else if operation != "embedding" {
		return nil, ErrInvalid
	}
	nonce, raw, err := h.searchPost(ctx, "result", map[string]string{"work_id": b.WorkID, "call_id": callID, "operation": operation})
	if err != nil {
		return nil, ErrInvalid
	}
	var result struct {
		Assertion string `json:"assertion"`
		Content   string `json:"content"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return nil, ErrInvalid
	}
	body, err := base64.StdEncoding.DecodeString(result.Content)
	if err != nil || base64.StdEncoding.EncodeToString(body) != result.Content {
		return nil, ErrInvalid
	}
	if _, err = h.verifier.VerifySearchResult(result.Assertion, b, nonce, callID, model, operation, wire, body); err != nil {
		return nil, ErrInvalid
	}
	return body, nil
}
func (h *HostAuthority) SearchDispatch(ctx context.Context, b SearchBinding, callID, operation string, input []byte) ([]byte, error) {
	if len(input) == 0 || len(input) > 2<<20 {
		return nil, ErrInvalid
	}
	// Regardless of a lost acknowledgement, only a signed result lookup is
	// performed afterwards; this method never makes a second dispatch.
	_, _, _ = h.searchPost(ctx, "dispatch", map[string]string{"work_id": b.WorkID, "call_id": callID, "operation": operation, "content": base64.StdEncoding.EncodeToString(input)})
	return h.SearchResult(ctx, b, callID, operation)
}
