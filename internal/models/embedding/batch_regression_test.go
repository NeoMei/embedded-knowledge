package embedding

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"testing/synctest"

	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/panjf2000/ants/v2"
	"github.com/stretchr/testify/require"
)

func TestBatchEmbedWaitsForAcceptedCallsWhenPoolRejectsSubmission(t *testing.T) {
	t.Setenv("BATCH_EMBED_SIZE", "1")
	synctest.Test(t, func(t *testing.T) {
		pool, err := ants.NewPool(1, ants.WithNonblocking(true), ants.WithDisablePurge(true))
		require.NoError(t, err)
		defer pool.Release()
		model := newFakeEmbedder("fixture")
		completed := make(chan error, 1)
		go func() {
			_, err := NewBatchEmbedder(pool).BatchEmbedWithPool(context.Background(), model, []string{"first", "second"})
			completed <- err
		}()
		<-model.enter
		synctest.Wait()
		var result error
		var returned bool
		select {
		case result = <-completed:
			returned = true
		default:
		}
		close(model.release)
		if !returned {
			result = <-completed
		}
		require.ErrorIs(t, result, ants.ErrPoolOverload)
		require.False(t, returned, "returned before the accepted request finished")
	})
}

func TestBatchEmbedReturnsErrorWithoutConcurrentErrorRace(t *testing.T) {
	t.Setenv("BATCH_EMBED_SIZE", "1")
	pool, err := ants.NewPool(4, ants.WithDisablePurge(true))
	require.NoError(t, err)
	defer pool.Release()
	broken := &errorBatchEmbedder{err: errors.New("upstream failed")}
	_, err = NewBatchEmbedder(pool).BatchEmbedWithPool(context.Background(), broken, []string{"a", "b", "c", "d"})
	require.ErrorIs(t, err, broken.err)
}

type errorBatchEmbedder struct{ err error }

func (e *errorBatchEmbedder) Embed(context.Context, string) ([]float32, error) { return nil, e.err }
func (e *errorBatchEmbedder) BatchEmbed(context.Context, []string) ([][]float32, error) {
	return nil, e.err
}
func (e *errorBatchEmbedder) BatchEmbedWithPool(context.Context, Embedder, []string) ([][]float32, error) {
	return nil, e.err
}
func (e *errorBatchEmbedder) GetModelName() string { return "test" }
func (e *errorBatchEmbedder) GetModelID() string   { return "test" }
func (e *errorBatchEmbedder) GetDimensions() int   { return 1 }

func TestBatchEmbedPreservesInputOrderAcrossConcurrentChunks(t *testing.T) {
	t.Setenv("BATCH_EMBED_SIZE", "1")
	pool, err := ants.NewPool(4, ants.WithDisablePurge(true))
	require.NoError(t, err)
	defer pool.Release()
	got, err := NewBatchEmbedder(pool).BatchEmbedWithPool(context.Background(), orderedBatchEmbedder{}, []string{"1", "2", "3", "4"})
	require.NoError(t, err)
	require.Equal(t, [][]float32{{1}, {2}, {3}, {4}}, got)
}

type orderedBatchEmbedder struct{}

func (orderedBatchEmbedder) Embed(context.Context, string) ([]float32, error) { panic("not used") }
func (orderedBatchEmbedder) BatchEmbed(_ context.Context, texts []string) ([][]float32, error) {
	results := make([][]float32, len(texts))
	for i, text := range texts {
		n, err := strconv.Atoi(text)
		if err != nil {
			return nil, err
		}
		results[i] = []float32{float32(n)}
	}
	return results, nil
}
func (orderedBatchEmbedder) BatchEmbedWithPool(context.Context, Embedder, []string) ([][]float32, error) {
	panic("not used")
}
func (orderedBatchEmbedder) GetModelName() string { return "test" }
func (orderedBatchEmbedder) GetModelID() string   { return "test" }
func (orderedBatchEmbedder) GetDimensions() int   { return 1 }

type managedOrdinalEmbedder struct{ indices chan int }

func (e *managedOrdinalEmbedder) BatchEmbed(ctx context.Context, texts []string) ([][]float32, error) {
	index, ok := api.ManagedBatchStart(ctx)
	if !ok {
		return nil, errors.New("missing batch index")
	}
	e.indices <- index
	result := make([][]float32, len(texts))
	for i := range result {
		result[i] = []float32{float32(index)}
	}
	return result, nil
}
func (e *managedOrdinalEmbedder) Embed(context.Context, string) ([]float32, error) {
	return nil, errors.New("unexpected")
}
func (e *managedOrdinalEmbedder) BatchEmbedWithPool(context.Context, Embedder, []string) ([][]float32, error) {
	return nil, errors.New("unexpected")
}
func (e *managedOrdinalEmbedder) GetModelName() string { return "test" }
func (e *managedOrdinalEmbedder) GetModelID() string   { return "test" }
func (e *managedOrdinalEmbedder) GetDimensions() int   { return 1 }
func TestManagedBatchUsesStableOffsetsForDuplicateText(t *testing.T) {
	t.Setenv("BATCH_EMBED_SIZE", "1")
	pool, err := ants.NewPool(2)
	require.NoError(t, err)
	defer pool.Release()
	model := &managedOrdinalEmbedder{indices: make(chan int, 2)}
	ctx := api.WithManagedJSON(context.Background(), func(context.Context, string, string, []byte) ([]byte, error) { return nil, errors.New("not invoked") })
	vectors, err := NewBatchEmbedder(pool).BatchEmbedWithPool(ctx, model, []string{"same", "same"})
	require.NoError(t, err)
	require.Equal(t, [][]float32{{0}, {1}}, vectors)
}
