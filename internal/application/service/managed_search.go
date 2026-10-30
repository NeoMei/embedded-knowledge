package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/types"
)

const managedSearchResponseMaxBytes = 1 << 20

// ManagedSearchResponse is the authenticated HTTP delivery format consumed by
// the normal SuperWagie host. Payload is base64 so its exact bytes survive JSON
// transport; MAC authenticates those bytes before the host parses them.
type ManagedSearchResponse struct {
	Payload string `json:"payload"`
	MAC     string `json:"mac"`
}

type managedSearchResponsePayload struct {
	Version       string                          `json:"version"`
	Scope         managedcapability.SearchBinding `json:"scope"`
	Nonce         string                          `json:"nonce"`
	WorkerBootID  string                          `json:"worker_boot_id"`
	ResultBase64  string                          `json:"result_base64"`
	ContentSHA256 string                          `json:"content_sha256"`
	IssuedAt      int64                           `json:"issued_at"`
	ExpiresAt     int64                           `json:"expires_at"`
}

// ManagedHybridSearchWithEvidence consumes the one-use request proof exactly
// once, performs a managed search, and returns a response authenticated with
// the existing callback key under the managed-search-response-v1 domain.
func (s *knowledgeBaseService) ManagedHybridSearchWithEvidence(ctx context.Context, tenant uint64, kbID, method, path string, body []byte, capability, proof string) (*ManagedSearchResponse, error) {
	w := s.managedWorker
	if w == nil || w.workerBootID == "" {
		return nil, ErrManagedWorkerUnavailable
	}
	claims, err := w.verifier.DecodeSearch(capability)
	if err != nil || claims.TenantID != tenant || claims.KnowledgeBaseID != kbID || w.host.SearchCheck(ctx, claims.SearchBinding) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	request, err := w.acceptProofClaims(ctx, method, path, body, proof, claims.WorkID, claims.ActorID, claims.AccountID)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	result, err := s.ManagedHybridSearch(ctx, kbID, capability)
	if err != nil || result == nil {
		return nil, ErrManagedWorkerUnavailable
	}
	// Revalidate live authority and both signed windows after retrieval. This is
	// a metadata check only; it cannot dispatch or repeat the paid query.
	if w.host.SearchCheck(ctx, claims.SearchBinding) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	if err = s.revalidateManagedSearchResult(ctx, tenant, kbID, claims.SearchBinding, result); err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	resultRaw, err := json.Marshal(result)
	if err != nil || len(resultRaw) == 0 || len(resultRaw) > managedSearchResponseMaxBytes {
		return nil, ErrManagedWorkerUnavailable
	}
	now := w.verifier.CurrentUnix()
	expires := min(now+30, claims.ExpiresAt, request.ExpiresAt)
	if now <= 0 || expires <= now || w.workerBootID == "" {
		return nil, ErrManagedWorkerUnavailable
	}
	digest := sha256.Sum256(resultRaw)
	payload := managedSearchResponsePayload{
		Version: "managed-search-response-v1", Scope: claims.SearchBinding, Nonce: request.Nonce,
		WorkerBootID: w.workerBootID, ResultBase64: base64.StdEncoding.EncodeToString(resultRaw),
		ContentSHA256: hex.EncodeToString(digest[:]), IssuedAt: now, ExpiresAt: expires,
	}
	payloadRaw, err := json.Marshal(payload)
	if err != nil || len(payloadRaw) > managedSearchResponseMaxBytes {
		return nil, ErrManagedWorkerUnavailable
	}
	// Finish all serialization before the last signed-window checks so no
	// callback or database work can occur between those checks and the MAC.
	if _, err = w.verifier.VerifySearch(capability, claims.SearchBinding); err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	if _, err = w.verifier.VerifyRequest(proof, method, path, body, claims.WorkID, claims.ActorID, claims.AccountID); err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	signingNow := w.verifier.CurrentUnix()
	if signingNow <= 0 || expires <= signingNow {
		return nil, ErrManagedWorkerUnavailable
	}
	return &ManagedSearchResponse{Payload: base64.StdEncoding.EncodeToString(payloadRaw), MAC: w.host.SearchResponseMAC(payloadRaw)}, nil
}

// revalidateManagedSearchResult runs only local SQLite reads after the wrapper's
// final asynchronous authority check. It binds the returned result back to the
// exact persisted completion, index registration and current source rows.
func (s *knowledgeBaseService) revalidateManagedSearchResult(ctx context.Context, tenant uint64, kbID string, b managedcapability.SearchBinding, result *types.RetrievalResult) error {
	w := s.managedWorker
	if w == nil || w.db == nil || result == nil || len(result.Results) != 1 || result.Results[0] == nil {
		return ErrManagedWorkerUnavailable
	}
	return w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		completion, refs, err := w.ReadCompletedIndexTx(ctx, tx, b.IndexWorkID, b.IndexRevision, b.CompletionDigest)
		if err != nil || completion.WorkID != b.IndexWorkID || completion.KnowledgeID != b.KnowledgeID || completion.Revision != b.IndexRevision {
			return ErrManagedWorkerUnavailable
		}
		indexed, err := w.lookup(ctx, tx, b.IndexWorkID)
		if err != nil || indexed.IndexBinding != b.IndexBinding || indexed.TenantID != tenant || indexed.KnowledgeBaseID != kbID || indexed.KnowledgeID != b.KnowledgeID || indexed.WorkID != b.IndexWorkID || indexed.ActorID != b.ActorID || indexed.AccountID != b.AccountID {
			return ErrManagedWorkerUnavailable
		}
		candidate := result.Results[0]
		if refs.Knowledge.TenantID != tenant || refs.Knowledge.KnowledgeBaseID != kbID || refs.Knowledge.ID != b.KnowledgeID || refs.Knowledge.ManagedWorkID != b.IndexWorkID || refs.Knowledge.ParseStatus != types.ParseStatusCompleted || refs.Knowledge.EnableStatus != "enabled" || candidate.ID != refs.Chunk.ID || candidate.Content != refs.Chunk.Content || candidate.KnowledgeID != refs.Knowledge.ID || candidate.KnowledgeTitle != refs.Knowledge.Title || candidate.KnowledgeFilename != refs.Knowledge.FileName || candidate.KnowledgeSource != refs.Knowledge.Source || candidate.ChunkType != refs.Chunk.ChunkType {
			return ErrManagedWorkerUnavailable
		}
		return nil
	})
}

// ManagedHybridSearch accepts only a host-signed capability. The query and
// selected document come from independently authenticated host work state.
func (s *knowledgeBaseService) ManagedHybridSearch(ctx context.Context, kbID, capability string) (*types.RetrievalResult, error) {
	w := s.managedWorker
	if w == nil {
		return nil, ErrManagedWorkerUnavailable
	}
	claims, err := w.verifier.DecodeSearch(capability)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	b := claims.SearchBinding
	tenant := types.MustTenantIDFromContext(ctx)
	if tenant != b.TenantID || kbID != b.KnowledgeBaseID || w.host.SearchCheck(ctx, b) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	document, err := s.kgRepo.GetKnowledgeByID(ctx, tenant, b.KnowledgeID)
	if err != nil || document == nil || document.KnowledgeBaseID != kbID || document.ManagedWorkID == "" || document.ParseStatus != types.ParseStatusCompleted || document.EnableStatus != "enabled" {
		return nil, ErrManagedWorkerUnavailable
	}
	if w.db == nil || w.aead == nil {
		return nil, ErrManagedWorkerUnavailable
	}
	indexed, err := w.lookup(ctx, w.db, document.ManagedWorkID)
	if err != nil || indexed.TenantID != tenant || indexed.KnowledgeBaseID != kbID || indexed.KnowledgeID != b.KnowledgeID || indexed.EmbeddingModel != b.EmbeddingModel || indexed.EmbeddingSpace != b.EmbeddingSpace {
		return nil, ErrManagedWorkerUnavailable
	}
	if !managedcapability.ValidIndexBinding(b.IndexBinding) || b.IndexBinding != indexed.IndexBinding || b.IndexWorkID != indexed.WorkID || b.ActorID != indexed.ActorID || b.AccountID != indexed.AccountID {
		return nil, ErrManagedWorkerUnavailable
	}
	var completion managedCompletion
	err = w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var e error
		completion, _, e = w.ReadCompletedIndexTx(ctx, tx, b.IndexWorkID, b.IndexRevision, b.CompletionDigest)
		return e
	})
	if err != nil {
		return nil, err
	}
	query, err := w.host.SearchSnapshot(ctx, b)
	if err != nil || !pilotText(query) {
		return nil, ErrManagedWorkerUnavailable
	}
	dispatch := func(callCtx context.Context, model, url string, body []byte) ([]byte, error) {
		ordinal, ok := api.ManagedBatchStart(callCtx)
		if !ok || ordinal != 0 || w.host.SearchCheck(callCtx, b) != nil {
			return nil, ErrManagedWorkerUnavailable
		}
		operation, wire := "embedding", "embeddings.create"
		switch model {
		case b.EmbeddingModel:
			var req struct {
				Model          string   `json:"model"`
				Input          []string `json:"input"`
				EncodingFormat string   `json:"encoding_format,omitempty"`
				Dimensions     int      `json:"dimensions,omitempty"`
			}
			dec := json.NewDecoder(strings.NewReader(string(body)))
			dec.DisallowUnknownFields()
			if dec.Decode(&req) != nil || req.Model != model || (req.Dimensions != 0 && req.Dimensions != managedcapability.EmbeddingDimensions) || len(req.Input) != 1 || req.Input[0] != string(query) {
				return nil, ErrManagedWorkerUnavailable
			}
		case b.RerankModel:
			operation, wire = "rerank", "rerank.create"
			var req struct {
				Model string `json:"model"`
				Input struct {
					Query     string   `json:"query"`
					Documents []string `json:"documents"`
				} `json:"input"`
				Parameters struct {
					TopN            int  `json:"top_n"`
					ReturnDocuments bool `json:"return_documents"`
				} `json:"parameters"`
			}
			dec := json.NewDecoder(strings.NewReader(string(body)))
			dec.DisallowUnknownFields()
			if dec.Decode(&req) != nil || req.Model != model || req.Input.Query != string(query) || len(req.Input.Documents) != 1 || req.Parameters.TopN != 1 || req.Parameters.ReturnDocuments {
				return nil, ErrManagedWorkerUnavailable
			}
		default:
			return nil, ErrManagedWorkerUnavailable
		}
		digest := sha256.Sum256(body)
		scope := managedjournal.Scope{TenantID: strconv.FormatUint(tenant, 10), ActorID: b.ActorID, AccountID: b.AccountID, TaskID: b.TaskID, LogicalID: b.WorkID, Operation: operation, Model: model, PlanDigest: hex.EncodeToString(digest[:]), Batch: ordinal}
		out, err := w.journal.Execute(callCtx, scope, body, func(c context.Context, callID string) ([]byte, error) {
			if w.host.SearchCheck(c, b) != nil {
				return nil, managedjournal.ErrDefinitelyNotSent
			}
			return w.host.SearchDispatch(c, b, callID, operation, body)
		})
		if errors.Is(err, managedjournal.ErrExpired) {
			// Expiry removes only the local payload, not the original paid call.
			// Revalidate current authority and accept only a signed SETTLED read;
			// this path cannot use absence proofs or invoke SearchDispatch.
			info, inspectErr := w.journal.Inspect(callCtx, scope, body)
			if inspectErr != nil || info.Status != "EXPIRED" {
				return nil, ErrManagedWorkerUnavailable
			}
			out, err = w.journal.RecoverExpired(callCtx, scope, body, time.Unix(claims.ExpiresAt, 0), func(c context.Context, callID string) ([]byte, error) {
				if callID != info.CallID || w.host.SearchCheck(c, b) != nil {
					return nil, ErrManagedWorkerUnavailable
				}
				if _, verifyErr := w.verifier.VerifySearch(capability, b); verifyErr != nil {
					return nil, ErrManagedWorkerUnavailable
				}
				result, readErr := w.host.SearchResult(c, b, callID, operation)
				if readErr != nil || w.host.SearchCheck(c, b) != nil {
					return nil, ErrManagedWorkerUnavailable
				}
				if _, verifyErr := w.verifier.VerifySearch(capability, b); verifyErr != nil {
					return nil, ErrManagedWorkerUnavailable
				}
				return result, nil
			})
			if err != nil {
				return nil, err
			}
		}
		if errors.Is(err, managedjournal.ErrUnresolved) {
			var absentCall string
			readResult := func(c context.Context, callID string) ([]byte, error) {
				if w.host.SearchCheck(c, b) != nil {
					return nil, ErrManagedWorkerUnavailable
				}
				result, readErr := w.host.SearchResultForInput(c, b, callID, operation, body)
				if errors.Is(readErr, managedcapability.ErrSearchNotSubmitted) {
					absentCall = callID
				}
				return result, readErr
			}
			out, err = w.journal.Recover(callCtx, scope, body, readResult)
			if errors.Is(err, managedjournal.ErrUnresolved) && absentCall != "" {
				// Recover itself stays read-only. Only a fresh, signed absence for
				// these exact bytes permits the original call to reach the host's
				// exclusive dispatch claim; ambiguous failures never enter here.
				info, inspectErr := w.journal.Inspect(callCtx, scope, body)
				if inspectErr != nil || info.Status != "DISPATCHED" || info.CallID != absentCall || w.host.SearchCheck(callCtx, b) != nil {
					return nil, ErrManagedWorkerUnavailable
				}
				if _, dispatchErr := w.host.SearchDispatch(callCtx, b, info.CallID, operation, body); dispatchErr != nil {
					return nil, dispatchErr
				}
				out, err = w.journal.Recover(callCtx, scope, body, readResult)
			}
		}
		if err != nil {
			return nil, err
		}
		info, err := w.journal.Inspect(callCtx, scope, body)
		if err != nil || info.Status != "COMPLETED" {
			return nil, ErrManagedWorkerUnavailable
		}
		confirmed, err := w.host.SearchResultForInput(callCtx, b, info.CallID, operation, body)
		if err != nil || !hmac.Equal(out, confirmed) || w.host.SearchCheck(callCtx, b) != nil {
			return nil, ErrManagedWorkerUnavailable
		}
		if operation == "embedding" {
			if err := validateManagedEmbeddingResult(confirmed); err != nil {
				return nil, err
			}
		}
		_ = wire
		return confirmed, nil
	}
	// Paid callbacks and journal writes are outside both short read transactions.
	callCtx := api.WithManagedBatchStart(api.WithManagedJSON(ctx, dispatch), 0)
	embedBody, _ := json.Marshal(struct {
		Model      string   `json:"model"`
		Input      []string `json:"input"`
		Dimensions int      `json:"dimensions"`
	}{b.EmbeddingModel, []string{string(query)}, 1024})
	raw, err := dispatch(callCtx, b.EmbeddingModel, "", embedBody)
	if err != nil {
		return nil, err
	}
	vector, err := managedVector(raw)
	if err != nil {
		return nil, err
	}
	var candidate *types.SearchResult
	err = w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var e error
		candidate, e = w.ReadManagedCandidatesTx(ctx, tx, completion, vector)
		return e
	})
	if err != nil {
		return nil, err
	}
	rerankBody, _ := json.Marshal(struct {
		Model string `json:"model"`
		Input struct {
			Query     string   `json:"query"`
			Documents []string `json:"documents"`
		} `json:"input"`
		Parameters struct {
			TopN            int  `json:"top_n"`
			ReturnDocuments bool `json:"return_documents"`
		} `json:"parameters"`
	}{Model: b.RerankModel, Input: struct {
		Query     string   `json:"query"`
		Documents []string `json:"documents"`
	}{string(query), []string{candidate.Content}}, Parameters: struct {
		TopN            int  `json:"top_n"`
		ReturnDocuments bool `json:"return_documents"`
	}{1, false}})
	raw, err = dispatch(callCtx, b.RerankModel, "", rerankBody)
	if err != nil {
		return nil, err
	}
	score, err := managedRerankScore(raw)
	if err != nil {
		return nil, err
	}
	candidate.Score = score
	if err = w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error { return w.RevalidateCompletionTx(ctx, tx, completion) }); err != nil {
		return nil, err
	}
	result := &types.RetrievalResult{Results: []*types.SearchResult{candidate}}
	// Retrieval and reranking may outlive the admission. Check live authority
	// again, then the original capability window after that asynchronous check.
	if w.host.SearchCheck(ctx, b) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	if _, err := w.verifier.VerifySearch(capability, b); err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	current, err := s.kgRepo.GetKnowledgeByID(ctx, tenant, b.KnowledgeID)
	if err != nil || current == nil || current.KnowledgeBaseID != kbID || current.ManagedWorkID != document.ManagedWorkID || current.ParseStatus != types.ParseStatusCompleted || current.EnableStatus != "enabled" {
		return nil, ErrManagedWorkerUnavailable
	}
	currentIndex, err := w.lookup(ctx, w.db, current.ManagedWorkID)
	if err != nil || currentIndex != indexed {
		return nil, ErrManagedWorkerUnavailable
	}
	return result, nil
}

func managedRerankScore(raw []byte) (float64, error) {
	var ranked struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Output  struct {
			Results []struct {
				Index *int     `json:"index"`
				Score *float64 `json:"relevance_score"`
			} `json:"results"`
		} `json:"output"`
	}
	var rankShape any
	if managedcapability.StrictJSON(raw, &rankShape) != nil || json.Unmarshal(raw, &ranked) != nil || ranked.Code != "" || len(ranked.Output.Results) != 1 || ranked.Output.Results[0].Index == nil || *ranked.Output.Results[0].Index != 0 || ranked.Output.Results[0].Score == nil || math.IsNaN(*ranked.Output.Results[0].Score) || math.IsInf(*ranked.Output.Results[0].Score, 0) || *ranked.Output.Results[0].Score < 0 || *ranked.Output.Results[0].Score > 1 {
		return 0, ErrManagedWorkerUnavailable
	}
	return *ranked.Output.Results[0].Score, nil
}

func (s *knowledgeBaseService) AuthorizeManagedSearch(ctx context.Context, tenant uint64, kb, method, path string, body []byte, capability, proof string) error {
	worker := s.managedWorker
	if worker == nil {
		return ErrManagedWorkerUnavailable
	}
	claims, err := worker.verifier.DecodeSearch(capability)
	if err != nil || claims.TenantID != tenant || claims.KnowledgeBaseID != kb || worker.host.SearchCheck(ctx, claims.SearchBinding) != nil {
		return ErrManagedWorkerUnavailable
	}
	return worker.acceptProof(ctx, method, path, body, proof, claims.WorkID, claims.ActorID, claims.AccountID)
}
