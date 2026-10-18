//go:build windows

package eventstore

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// lockDirectory obtains a nonblocking exclusive writer lock; closing the returned file or
// process exit releases it.
func lockDirectory(directory string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(directory, ".writer.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("open event writer lock failed")
	}
	if windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}) != nil {
		_ = f.Close()
		return nil, errors.New("event storage already has a writer")
	}
	return f, nil
}
