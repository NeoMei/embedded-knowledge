package embedding

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/Tencent/WeKnora/internal/models/api"
	"github.com/Tencent/WeKnora/internal/models/utils"
	"github.com/panjf2000/ants/v2"
)

type batchEmbedder struct {
	pool *ants.Pool
}

func NewBatchEmbedder(pool *ants.Pool) EmbedderPooler {
	return &batchEmbedder{pool: pool}
}

type textEmbedding struct {
	text    string
	results []float32
}

func (e *batchEmbedder) BatchEmbedWithPool(ctx context.Context, model Embedder, texts []string) ([][]float32, error) {
	// Create goroutine pool for concurrent processing of document chunks
	var wg sync.WaitGroup
	var mu sync.Mutex  // For synchronizing access to error
	var firstErr error // Record the first error that occurs
	batchSizeStr := os.Getenv("BATCH_EMBED_SIZE")
	if batchSizeStr == "" {
		batchSizeStr = "5"
	}
	batchSize, err := strconv.Atoi(batchSizeStr)
	if err != nil {
		return nil, err
	}
	textEmbeddings := utils.MapSlice(texts, func(text string) *textEmbedding {
		return &textEmbedding{text: text}
	})

	// Function to process each document chunk
	processChunk := func(texts []*textEmbedding, start int) func() {
		return func() {
			defer wg.Done()
			// If an error has already occurred, don't continue processing
			mu.Lock()
			failed := firstErr != nil
			mu.Unlock()
			if failed {
				return
			}
			// Embed text
			chunkCtx := api.WithManagedBatchStart(ctx, start)
			embedding, err := model.BatchEmbed(chunkCtx, utils.MapSlice(texts, func(text *textEmbedding) string {
				return text.text
			}))
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			if len(embedding) != len(texts) {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("embedding model returned %d embeddings for %d inputs", len(embedding), len(texts))
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			for i, text := range texts {
				if text == nil {
					continue
				}
				text.results = embedding[i]
			}
			mu.Unlock()
		}
	}

	// Submit all tasks to the goroutine pool
	var submitErr error
	for index, texts := range utils.ChunkSlice(textEmbeddings, batchSize) {
		wg.Add(1)
		if err := e.pool.Submit(processChunk(texts, index*batchSize)); err != nil {
			// This job was not accepted and will never call Done. Drain every
			// accepted job before reporting the submission failure.
			wg.Done()
			submitErr = err
			break
		}
	}

	// Wait for all tasks to complete
	wg.Wait()

	if submitErr != nil {
		return nil, submitErr
	}

	// Check if any errors occurred
	if firstErr != nil {
		return nil, firstErr
	}

	results := utils.MapSlice(textEmbeddings, func(text *textEmbedding) []float32 {
		return text.results
	})
	return results, nil
}
