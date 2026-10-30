//go:build darwin || linux

package service

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestManagedKeyFileRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0700))
	key := bytes.Repeat([]byte{0x42}, 32)
	file := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(file, key, 0600))
	got, err := readManagedKeyFile(file)
	require.NoError(t, err)
	require.Equal(t, key, got)

	require.NoError(t, os.Chmod(file, 0640))
	_, err = readManagedKeyFile(file)
	require.Error(t, err, "group-readable key")
	require.NoError(t, os.Chmod(file, 0600))
	require.NoError(t, os.Chmod(dir, 0750))
	_, err = readManagedKeyFile(file)
	require.Error(t, err, "non-private parent")
	require.NoError(t, os.Chmod(dir, 0700))

	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(file, link))
	_, err = readManagedKeyFile(link)
	require.Error(t, err, "key symlink")
	parentLink := filepath.Join(t.TempDir(), "parent")
	require.NoError(t, os.Symlink(dir, parentLink))
	_, err = readManagedKeyFile(filepath.Join(parentLink, "key"))
	require.Error(t, err, "parent symlink")

	_, err = readManagedKeyFile("key")
	require.Error(t, err, "relative path")
	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, unix.Mkfifo(fifo, 0600))
	_, err = readManagedKeyFile(fifo)
	require.Error(t, err, "fifo must be rejected without blocking")
	require.NoError(t, os.WriteFile(file, key[:31], 0600))
	_, err = readManagedKeyFile(file)
	require.Error(t, err, "short key")
	require.NoError(t, os.WriteFile(file, append(key, 1), 0600))
	_, err = readManagedKeyFile(file)
	require.Error(t, err, "oversized key")
}
