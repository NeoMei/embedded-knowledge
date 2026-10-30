package repository

import (
	"bytes"
	"context"
	"log"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestReferenceLookupDoesNotLogFilePath(t *testing.T) {
	var output bytes.Buffer
	logger := gormlogger.New(log.New(&output, "", 0), gormlogger.Config{LogLevel: gormlogger.Info, SlowThreshold: time.Second})
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.Knowledge{}))
	output.Reset()
	_, err = (&knowledgeRepository{db: db}).GetKnowledgeByFilePath(context.Background(), 1, "kb", "ref:///private/secret-filename.txt")
	require.NoError(t, err)
	require.NotContains(t, output.String(), "secret-filename.txt")
}
