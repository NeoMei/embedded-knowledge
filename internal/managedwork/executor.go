// Package managedwork composes verified work admission with a durable call
// journal. It is intentionally not registered to an HTTP route or worker.
package managedwork

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/managedjournal"
)

var ErrUnauthorized = errors.New("managed work authorization unavailable")

// Batch is obtained from a server-owned persisted work plan, never directly
// from an untrusted request. InputDigest hashes exactly one frozen wire batch;
// the capability's document digest binds the independently admitted document.
type Batch struct {
	Binding                                   managedcapability.Binding
	Operation, Model, PlanDigest, InputDigest string
	Ordinal                                   int
}

// Authority must retrieve the original immutable work plan and verify current
// actor, payer, task, document access and authorization for model/operation.
// It must fail closed on unavailable identity or revocation data. A signature
// alone does not prove current authorization. No caller-supplied payer may be
// used as authority.
type Authority interface {
	Resolve(ctx context.Context, workID, operation string, batch int) (Batch, error)
}

type Executor struct {
	verifier      *managedcapability.Verifier
	journal       *managedjournal.Journal
	authority     Authority
	currentUser   func(context.Context) (string, error)
	verifyReceipt func(context.Context, string, Batch, []byte) error
}

// currentUser must derive the active user from an independently authenticated
// request or server-owned worker session, never from the capability itself.
// verifyReceipt is a trusted adapter to the independent settlement authority;
// it must verify actor, payer, task, call and the exact response digest. A
// sender's statement that it settled is insufficient.
func New(verifier *managedcapability.Verifier, journal *managedjournal.Journal, authority Authority, currentUser func(context.Context) (string, error), verifyReceipt func(context.Context, string, Batch, []byte) error) (*Executor, error) {
	if verifier == nil || journal == nil || authority == nil || currentUser == nil || verifyReceipt == nil {
		return nil, ErrUnauthorized
	}
	return &Executor{verifier: verifier, journal: journal, authority: authority, currentUser: currentUser, verifyReceipt: verifyReceipt}, nil
}

// Execute must be supplied a sender that returns output only after independent
// verification of the central settled receipt. It never authorizes a charge by
// itself. A revoked caller cannot obtain a previously stored result.
func (e *Executor) Execute(ctx context.Context, token, workID, operation string, ordinal int, input []byte, send func(context.Context, string, []byte) ([]byte, error)) ([]byte, error) {
	if e == nil || ctx == nil || send == nil || len(input) == 0 || len(input) > 8<<20 {
		return nil, ErrUnauthorized
	}
	frozen := append([]byte(nil), input...)
	digest := sha256.Sum256(frozen)
	verify := func() (Batch, error) {
		item, err := e.authority.Resolve(ctx, workID, operation, ordinal)
		if err != nil || ctx.Err() != nil || item.Binding.WorkID != workID || item.Operation != operation || item.Ordinal != ordinal || item.InputDigest != hex.EncodeToString(digest[:]) {
			return Batch{}, ErrUnauthorized
		}
		actor, err := e.currentUser(ctx)
		if err != nil || actor == "" || actor != item.Binding.ActorID {
			return Batch{}, ErrUnauthorized
		}
		if _, err = e.verifier.Verify(token, item.Binding); err != nil {
			return Batch{}, ErrUnauthorized
		}
		return item, nil
	}
	item, err := verify()
	if err != nil {
		return nil, err
	}
	scope := managedjournal.Scope{TenantID: strconv.FormatUint(item.Binding.TenantID, 10), ActorID: item.Binding.ActorID, AccountID: item.Binding.AccountID, TaskID: item.Binding.TaskID, LogicalID: item.Binding.WorkID, Operation: item.Operation, Model: item.Model, PlanDigest: item.PlanDigest, Batch: item.Ordinal}
	result, err := e.journal.Execute(ctx, scope, frozen, func(callCtx context.Context, callID string) ([]byte, error) {
		current, e2 := verify()
		if e2 != nil || current != item {
			return nil, managedjournal.ErrDefinitelyNotSent
		}
		output, sendErr := send(callCtx, callID, append([]byte(nil), frozen...))
		// The transport is not trusted to assert that no bytes were sent.
		// Only the pre-dispatch authorization check above can do so here.
		if errors.Is(sendErr, managedjournal.ErrDefinitelyNotSent) {
			return nil, managedjournal.ErrUnresolved
		}
		if sendErr == nil && (len(output) == 0 || e.verifyReceipt(callCtx, callID, item, output) != nil) {
			return nil, managedjournal.ErrUnresolved
		}
		return output, sendErr
	})
	if err != nil {
		return nil, err
	}
	info, err := e.journal.Inspect(ctx, scope, frozen)
	if err != nil || info.Status != "COMPLETED" || e.verifyReceipt(ctx, info.CallID, item, result) != nil {
		return nil, ErrUnauthorized
	}
	current, err := verify()
	if err != nil || current != item {
		return nil, ErrUnauthorized
	}
	return result, nil
}
