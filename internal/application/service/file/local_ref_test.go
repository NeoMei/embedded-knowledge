package file

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	secutils "github.com/Tencent/WeKnora/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestReferenceFileIsReadInPlaceAndNeverDeleted(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "notes.md")
	require.NoError(t, os.WriteFile(sourcePath, []byte("hello"), 0o644))

	svc := NewLocalFileService(baseDir, "")
	refPath := secutils.ReferenceFilePath(sourcePath)

	reader, err := svc.GetFile(context.Background(), refPath)
	require.NoError(t, err)
	content, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	require.Equal(t, "hello", string(content))

	url, err := svc.GetFileURL(context.Background(), refPath)
	require.NoError(t, err)
	require.Equal(t, refPath, url)

	require.NoError(t, svc.DeleteFile(context.Background(), refPath))
	_, err = os.Stat(sourcePath)
	require.NoError(t, err, "deleting the index entry must not delete the source file")
}

func TestReferenceFileRejectsSymlinkAndMissingFile(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	svc := NewLocalFileService(baseDir, "")

	realPath := filepath.Join(t.TempDir(), "real.md")
	require.NoError(t, os.WriteFile(realPath, []byte("x"), 0o644))
	linkPath := filepath.Join(t.TempDir(), "link.md")
	require.NoError(t, os.Symlink(realPath, linkPath))

	_, err := svc.GetFile(context.Background(), secutils.ReferenceFilePath(linkPath))
	require.Error(t, err)

	_, err = svc.GetFile(context.Background(), secutils.ReferenceFilePath(filepath.Join(t.TempDir(), "gone.md")))
	require.Error(t, err)
}

func TestCloningAReferenceMakesARealCopy(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "report.pdf")
	require.NoError(t, os.WriteFile(sourcePath, []byte("pdf-bytes"), 0o644))

	svc := NewLocalFileService(baseDir, "")
	clonedPath, err := svc.CopyFile(context.Background(), secutils.ReferenceFilePath(sourcePath), 1, "knowledge-1")
	require.NoError(t, err)
	require.NotEqual(t, secutils.ReferenceFilePath(sourcePath), clonedPath)

	copied, err := svc.GetFile(context.Background(), clonedPath)
	require.NoError(t, err)
	content, err := io.ReadAll(copied)
	require.NoError(t, err)
	require.NoError(t, copied.Close())
	require.Equal(t, "pdf-bytes", string(content))
}
