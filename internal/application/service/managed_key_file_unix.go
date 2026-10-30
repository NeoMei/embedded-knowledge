//go:build darwin || linux

package service

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// readManagedKeyFile opens the parent and the key without following symlinks,
// then checks and reads the same file descriptor. Parent privacy is necessary
// because the worker key is a bearer secret shared with the local host.
func readManagedKeyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrManagedWorkerUnavailable
	}
	dir, name := filepath.Split(path)
	if name == "" || name == "." || name == ".." {
		return nil, ErrManagedWorkerUnavailable
	}
	parentFD, err := unix.Open(filepath.Clean(dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if unix.Fstat(parentFD, &parent) != nil || parent.Uid != uint32(os.Geteuid()) || parent.Mode&0077 != 0 {
		return nil, ErrManagedWorkerUnavailable
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Geteuid()) || info.Mode&0077 != 0 || info.Size != 32 {
		return nil, ErrManagedWorkerUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(data) != 32 {
		return nil, ErrManagedWorkerUnavailable
	}
	return data, nil
}
