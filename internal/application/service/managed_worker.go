package service

import (
	"context"
	"errors"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/types"
)

var ErrManagedWorkerUnavailable = errors.New("managed knowledge worker unavailable")

type managedSnapshotKey struct{}

// The runtime must verify the persisted binding, live host assertion, signed
// immutable snapshot and provide a settlement-aware model dispatcher.
// No HTTP request can construct this context.
type managedWorkerRuntime interface {
	Prepare(context.Context, types.DocumentProcessPayload) (*managedWorkerAdmission, error)
	Register(context.Context, uint64, string, string, string) (managedcapability.Binding, error)
}
type managedWorkerAdmission struct {
	Context  context.Context
	Snapshot []byte
}

type managedReferenceKey struct{}

// CreateManagedKnowledgeFromPath is exposed only to the controlled handler.
// Register must verify the host's signature and live user authorization, and
// retain the binding before any knowledge row or worker payload is created.
func (s *knowledgeService) CreateManagedKnowledgeFromPath(ctx context.Context, kbID, path, capability string) (*types.Knowledge, error) {
	if s.managedWorker == nil {
		return nil, ErrManagedWorkerUnavailable
	}
	tenant, ok := ctx.Value(types.TenantIDContextKey).(uint64)
	if !ok || tenant == 0 {
		return nil, ErrManagedWorkerUnavailable
	}
	binding, err := s.managedWorker.Register(ctx, tenant, kbID, path, capability)
	if err != nil || binding.TenantID != tenant || binding.KnowledgeBaseID != kbID || binding.WorkID == "" || binding.KnowledgeID == "" {
		return nil, ErrManagedWorkerUnavailable
	}
	ctx = context.WithValue(ctx, managedReferenceKey{}, binding)
	return s.CreateKnowledgeFromPath(ctx, kbID, path, "", "", nil, nil, "", nil)
}

func (s *knowledgeService) AuthorizeManagedReference(ctx context.Context, tenant uint64, kb, method, path string, body []byte, capability, proof string) error {
	worker, ok := s.managedWorker.(*pilotManagedWorker)
	if !ok || worker == nil {
		return ErrManagedWorkerUnavailable
	}
	claims, err := worker.verifier.DecodeVerified(capability)
	if err != nil || claims.TenantID != tenant || claims.KnowledgeBaseID != kb || worker.host.Check(ctx, claims.Binding) != nil {
		return ErrManagedWorkerUnavailable
	}
	return worker.acceptProof(ctx, method, path, body, proof, claims.WorkID, claims.ActorID, claims.AccountID)
}

// ManagedStatus contains no source path, capability or document content.
type ManagedStatus struct {
	ID          string `json:"id"`
	ParseStatus string `json:"parse_status"`
}

// ManagedKnowledgeStatus checks a one-use request proof and current source
// authority before returning the persisted state of exactly that work.
func (s *knowledgeService) ManagedKnowledgeStatus(ctx context.Context, tenant uint64, kb, method, path string, body []byte, capability, proof string) (*ManagedStatus, error) {
	w, ok := s.managedWorker.(*pilotManagedWorker)
	if !ok || w == nil || s.repo == nil {
		return nil, ErrManagedWorkerUnavailable
	}
	claims, err := w.verifier.DecodeVerified(capability)
	if err != nil || claims.TenantID != tenant || claims.KnowledgeBaseID != kb {
		return nil, ErrManagedWorkerUnavailable
	}
	if err := s.AuthorizeManagedReference(ctx, tenant, kb, method, path, body, capability, proof); err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	bound, err := w.lookup(ctx, w.db, claims.WorkID)
	if err != nil || bound != claims.Binding {
		return nil, ErrManagedWorkerUnavailable
	}
	knowledge, err := s.repo.GetKnowledgeByID(ctx, tenant, claims.KnowledgeID)
	if err != nil || knowledge == nil || knowledge.ID != claims.KnowledgeID || knowledge.TenantID != tenant || knowledge.KnowledgeBaseID != kb || knowledge.ManagedWorkID != claims.WorkID {
		return nil, ErrManagedWorkerUnavailable
	}
	if w.host.Check(ctx, claims.Binding) != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	if _, err := w.verifier.Verify(capability, bound); err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	return &ManagedStatus{ID: knowledge.ID, ParseStatus: knowledge.ParseStatus}, nil
}
