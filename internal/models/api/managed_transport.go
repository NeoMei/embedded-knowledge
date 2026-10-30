package api

import "context"

// ManagedJSON is injected only by a trusted server-side execution context. It
// must authorize the operation and independently verify its settled response.
// It receives no provider credentials. Never derive this callback from request
// headers or a shared local model key.
type ManagedJSON func(ctx context.Context, model, url string, body []byte) ([]byte, error)

type managedJSONKey struct{}

func WithManagedJSON(ctx context.Context, dispatch ManagedJSON) context.Context {
	return context.WithValue(ctx, managedJSONKey{}, dispatch)
}

func managedJSON(ctx context.Context) (ManagedJSON, bool) {
	if ctx == nil {
		return nil, false
	}
	dispatch, ok := ctx.Value(managedJSONKey{}).(ManagedJSON)
	return dispatch, ok && dispatch != nil
}

func ManagedJSONActive(ctx context.Context) bool {
	_, ok := managedJSON(ctx)
	return ok
}

type managedBatchStartKey struct{}

// WithManagedBatchStart sets a stable position in the frozen input plan. It
// does nothing for native execution; duplicate text at distinct positions
// remains distinct. The full batch plan must be fixed before any dispatch.
func WithManagedBatchStart(ctx context.Context, start int) context.Context {
	if _, ok := managedJSON(ctx); !ok {
		return ctx
	}
	return context.WithValue(ctx, managedBatchStartKey{}, start)
}
func ManagedBatchStart(ctx context.Context) (int, bool) {
	if _, ok := managedJSON(ctx); !ok {
		return 0, false
	}
	index, ok := ctx.Value(managedBatchStartKey{}).(int)
	return index, ok && index >= 0
}
