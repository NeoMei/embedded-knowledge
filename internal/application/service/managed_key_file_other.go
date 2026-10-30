//go:build !darwin && !linux && !windows

package service

// The managed pilot requires descriptor-relative no-follow opens; unsupported
// platforms stay closed until an equivalent implementation is available.
func readManagedKeyFile(string) ([]byte, error) {
	return nil, ErrManagedWorkerUnavailable
}
