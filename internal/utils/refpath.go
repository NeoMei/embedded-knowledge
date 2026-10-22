package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReferenceScheme marks a knowledge file that is indexed where it lives
// instead of being copied into storage. The remainder is an absolute path.
const ReferenceScheme = "ref://"

// ReferencePath reports whether filePath is a reference path and, if so,
// returns the absolute path behind it. It does not touch the filesystem.
func ReferencePath(filePath string) (string, bool) {
	if !strings.HasPrefix(filePath, ReferenceScheme) {
		return "", false
	}
	abs := strings.TrimSpace(strings.TrimPrefix(filePath, ReferenceScheme))
	if !filepath.IsAbs(abs) {
		return "", false
	}
	return filepath.Clean(abs), true
}

// ReferenceFilePath builds the stored form of a reference path.
func ReferenceFilePath(absPath string) string {
	return ReferenceScheme + filepath.Clean(absPath)
}

// ValidateReferencePath checks that path names an existing regular file that is
// not a symlink, and returns its cleaned absolute form. Callers that register
// a reference and callers that read one share this check so a path can never
// mean different things at different times.
func ValidateReferencePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("cannot read path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("path must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("path must be a regular file")
	}
	return clean, nil
}
