package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/types"
)

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
		if errors.Is(err, managedjournal.ErrUnresolved) {
			out, err = w.journal.Recover(callCtx, scope, body, func(c context.Context, callID string) ([]byte, error) {
				if w.host.SearchCheck(c, b) != nil {
					return nil, ErrManagedWorkerUnavailable
				}
				return w.host.SearchResult(c, b, callID, operation)
			})
		}
		if err != nil {
			return nil, err
		}
		info, err := w.journal.Inspect(callCtx, scope, body)
		if err != nil || info.Status != "COMPLETED" {
			return nil, ErrManagedWorkerUnavailable
		}
		confirmed, err := w.host.SearchResult(callCtx, b, info.CallID, operation)
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
	managedCtx := api.WithManagedJSON(ctx, dispatch)
	params := types.SearchParams{QueryText: string(query), MatchCount: 1, DisableKeywordsMatch: true, KnowledgeIDs: []string{b.KnowledgeID}, SkipContextEnrichment: true, Rerank: &types.RerankOptions{TopK: 1}}
	result, err := s.HybridSearchWithRerank(managedCtx, kbID, params)
	if err != nil {
		return nil, err
	}
	for _, r := range result.Results {
		if r == nil || r.KnowledgeID != b.KnowledgeID {
			return nil, ErrManagedWorkerUnavailable
		}
	}
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
