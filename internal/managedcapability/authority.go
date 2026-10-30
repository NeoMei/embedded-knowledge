package managedcapability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HostAuthority checks the currently logged-in owner through a fresh,
// nonce-bound signed host response. A loopback URL is transport only; the
// signed assertion, not the local address, is the source of authority.
type HostAuthority struct {
	endpoint    string
	verifier    *Verifier
	client      *http.Client
	callbackKey []byte
}

func NewHostAuthority(endpoint string, verifier *Verifier, client *http.Client, callbackKey []byte) (*HostAuthority, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || net.ParseIP(u.Hostname()) == nil || u.User != nil || u.Path != "/internal/knowledge-work/authorize" || u.RawQuery != "" || u.Fragment != "" || verifier == nil || client == nil || len(callbackKey) != 32 {
		return nil, ErrInvalid
	}
	copyClient := *client
	copyClient.Timeout = 5 * time.Second
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HostAuthority{endpoint: endpoint, verifier: verifier, client: &copyClient, callbackKey: append([]byte(nil), callbackKey...)}, nil
}
func (h *HostAuthority) Check(ctx context.Context, binding Binding) error {
	if h == nil || ctx == nil || !validBinding(binding) {
		return ErrInvalid
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ErrInvalid
	}
	nonce := hex.EncodeToString(random[:])
	raw, err := json.Marshal(map[string]string{"work_id": binding.WorkID, "nonce": nonce})
	if err != nil {
		return ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(raw))
	if err != nil {
		return ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := h.do(request, raw)
	if err != nil {
		return ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(data) > 16384 {
		return ErrInvalid
	}
	var result struct {
		Assertion string `json:"assertion"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if StrictJSON(data, &result) != nil || decoder.Decode(&result) != nil {
		return ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	if _, err = h.verifier.VerifyActive(result.Assertion, binding, nonce); err != nil || ctx.Err() != nil {
		return ErrInvalid
	}
	return nil
}

// Snapshot obtains authenticated bytes to parse. It does not reopen a mutable
// source file after the host has verified the work's original content MAC.
func (h *HostAuthority) Snapshot(ctx context.Context, binding Binding) ([]byte, error) {
	if h == nil || ctx == nil || !validBinding(binding) {
		return nil, ErrInvalid
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, ErrInvalid
	}
	nonce := hex.EncodeToString(random[:])
	body, err := json.Marshal(map[string]string{"work_id": binding.WorkID, "nonce": nonce})
	if err != nil {
		return nil, ErrInvalid
	}
	endpoint := strings.TrimSuffix(h.endpoint, "/authorize") + "/snapshot"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := h.do(request, body)
	if err != nil {
		return nil, ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 12<<20))
	if err != nil || len(data) >= 12<<20 {
		return nil, ErrInvalid
	}
	var result struct {
		Assertion string `json:"assertion"`
		Content   string `json:"content"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if StrictJSON(data, &result) != nil || decoder.Decode(&result) != nil {
		return nil, ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	content, err := base64.StdEncoding.DecodeString(result.Content)
	if err != nil || base64.StdEncoding.EncodeToString(content) != result.Content {
		return nil, ErrInvalid
	}
	if _, err = h.verifier.VerifySnapshot(result.Assertion, binding, nonce, content); err != nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	return content, nil
}

// Result is read-only: the host only signs bytes returned by an authenticated
// gateway result-read, after that gateway has verified the settled call.
func (h *HostAuthority) Result(ctx context.Context, binding Binding, callID, model, operation, wire string) ([]byte, error) {
	raw, _, err := h.ResultWithEvidence(ctx, binding, callID, model, operation, wire)
	return raw, err
}

func (h *HostAuthority) ResultWithEvidence(ctx context.Context, binding Binding, callID, model, operation, wire string) ([]byte, ResultClaims, error) {
	if h == nil || ctx == nil || !validBinding(binding) || !identifier.MatchString(callID) {
		return nil, ResultClaims{}, ErrInvalid
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, ResultClaims{}, ErrInvalid
	}
	nonce := hex.EncodeToString(random[:])
	body, err := json.Marshal(map[string]string{"work_id": binding.WorkID, "nonce": nonce, "call_id": callID})
	if err != nil {
		return nil, ResultClaims{}, ErrInvalid
	}
	endpoint := strings.TrimSuffix(h.endpoint, "/authorize") + "/result"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ResultClaims{}, ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := h.do(request, body)
	if err != nil {
		return nil, ResultClaims{}, ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ResultClaims{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 24<<20))
	if err != nil || len(data) >= 24<<20 {
		return nil, ResultClaims{}, ErrInvalid
	}
	var result struct {
		Assertion string `json:"assertion"`
		Content   string `json:"content"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if StrictJSON(data, &result) != nil || decoder.Decode(&result) != nil {
		return nil, ResultClaims{}, ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, ResultClaims{}, ErrInvalid
	}
	content, err := base64.StdEncoding.DecodeString(result.Content)
	if err != nil || base64.StdEncoding.EncodeToString(content) != result.Content {
		return nil, ResultClaims{}, ErrInvalid
	}
	claims, err := h.verifier.VerifyResult(result.Assertion, binding, nonce, callID, model, operation, wire, content)
	if err != nil || ctx.Err() != nil {
		return nil, ResultClaims{}, ErrInvalid
	}
	return content, claims, nil
}

// Dispatch sends exactly one bounded embedding request through the trusted
// host, then reads the authenticated settled result. Unknown dispatch outcomes
// are never retried; a read-only result lookup may safely resolve them.
func (h *HostAuthority) Dispatch(ctx context.Context, binding Binding, callID, model string, input []byte) ([]byte, error) {
	if h == nil || ctx == nil || !validBinding(binding) || !identifier.MatchString(callID) || len(input) == 0 || len(input) > 2<<20 {
		return nil, ErrInvalid
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, ErrInvalid
	}
	nonce := hex.EncodeToString(random[:])
	body, err := json.Marshal(map[string]string{"work_id": binding.WorkID, "nonce": nonce, "call_id": callID, "content": base64.StdEncoding.EncodeToString(input)})
	if err != nil {
		return nil, ErrInvalid
	}
	endpoint := strings.TrimSuffix(h.endpoint, "/authorize") + "/dispatch"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := h.do(request, body)
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
	}
	// Even a failed or interrupted dispatch may have settled. This is a read,
	// never another provider submission. A missing result stays unresolved.
	return h.Result(ctx, binding, callID, model, "embedding", "embeddings.create")
}

// do authenticates the worker to the local host. The request nonce is fresh
// for each call and also bound to the exact path and payload.
func (h *HostAuthority) do(req *http.Request, body []byte) (*http.Response, error) {
	var payload struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Nonce) != 64 {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(body)
	mac := hmac.New(sha256.New, h.callbackKey)
	timestamp := fmt.Sprint(time.Now().Unix())
	_, _ = fmt.Fprintf(mac, "weknora-callback-v2\n%s\n%s\n%x\n%s\n%s", req.Method, req.URL.Path, sum, payload.Nonce, timestamp)
	req.Header.Set("X-WeKnora-Worker-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-WeKnora-Worker-Time", timestamp)
	return h.client.Do(req)
}
