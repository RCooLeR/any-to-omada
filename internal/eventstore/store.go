// Package eventstore retains redacted native payloads and lens-routed event
// edges in bounded JSONL segments. Each restart creates a new segment.
package eventstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"
)

var segmentName = regexp.MustCompile(`^events-([0-9]{20})\.jsonl$`)

// Record retains receipt time separately from timestamps inside a camera payload.
type Record struct {
	SchemaVersion int       `json:"schema_version"`
	ReceivedUTC   time.Time `json:"received_utc"`
	DeviceID      string    `json:"device_id"`
	Protocol      string    `json:"protocol"`
	Kind          string    `json:"kind"`
	Data          any       `json:"data"`
}

// Store owns an exclusively opened segment and its bounded retention set.
// The mutex serializes record writes and file rotation; callers never hold other locks.
type Store struct {
	mu           sync.Mutex
	directory    string
	segmentBytes int64
	maxSegments  int
	redactor     redactor
	file         *os.File
	lock         *os.File
	number       uint64
	bytes        int64
	closed       bool
}

// Open resumes owned segments without overwriting existing logs. Only exact
// events-NNN.jsonl files are eligible for rotation; other directory files stay intact.
func Open(directory string, segmentBytes int64, segments int, secrets []string) (*Store, error) {
	if segmentBytes < 4<<20 || segmentBytes > 64<<20 || segments < 2 || segments > 64 {
		return nil, errors.New("invalid event retention bounds")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errors.New("create event storage failed")
	}
	lock, err := lockDirectory(directory)
	if err != nil {
		return nil, err
	}
	s := &Store{directory: directory, segmentBytes: segmentBytes, maxSegments: segments, lock: lock}
	opened := false
	defer func() {
		if !opened {
			_ = lock.Close()
		}
	}()
	for _, secret := range secrets {
		if secret != "" {
			s.redactor.secrets = append(s.redactor.secrets, secret)
		}
	}
	files, err := s.owned()
	if err != nil {
		return nil, err
	}
	if len(files) > 0 {
		n, err := strconv.ParseUint(segmentName.FindStringSubmatch(files[len(files)-1])[1], 10, 64)
		if err != nil || n == ^uint64(0) {
			return nil, errors.New("event segment sequence exhausted")
		}
		s.number = n
	}
	if err := s.rotate(); err != nil {
		return nil, err
	}
	opened = true
	return s, nil
}

// owned lists sorted segment names belonging to this store and refuses matching nonregular
// files before retention can touch them.
func (s *Store) owned() ([]string, error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, errors.New("read event storage failed")
	}
	files := []string{}
	for _, entry := range entries {
		if !segmentName.MatchString(entry.Name()) {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, errors.New("event segment is not a regular file")
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)
	return files, nil
}

// rotate syncs the old segment, exclusively creates its successor, and retires only excess
// owned segments; callers serialize it with writes.
func (s *Store) rotate() error {
	if s.file != nil {
		if err := s.file.Sync(); err != nil {
			return errors.New("sync event storage failed")
		}
		if err := s.file.Close(); err != nil {
			return errors.New("close event segment failed")
		}
		s.file = nil
	}
	s.number++
	name := filepath.Join(s.directory, fmt.Sprintf("events-%020d.jsonl", s.number))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("create event segment failed")
	}
	s.file, s.bytes = f, 0
	files, err := s.owned()
	if err != nil {
		_ = f.Close()
		s.file = nil
		return err
	}
	for len(files) > s.maxSegments {
		if err := os.Remove(filepath.Join(s.directory, files[0])); err != nil {
			_ = f.Close()
			s.file = nil
			return errors.New("retire event segment failed")
		}
		files = files[1:]
	}
	return nil
}

// Write atomically appends one sanitized line and rotates before its size bound.
// The directory must be private and exclusively owned by one running process.
func (s *Store) Write(deviceID, protocol, kind string, data any) error {
	encoded, err := json.Marshal(data)
	if err != nil || len(encoded) > 3<<20 {
		return errors.New("event payload exceeds storage bounds")
	}
	var decoded any
	if decodeJSON(encoded, &decoded) != nil {
		return errors.New("event payload is invalid")
	}
	record := Record{1, time.Now().UTC(), deviceID, protocol, kind, s.redactor.redact(decoded, 0)}
	line, err := json.Marshal(record)
	if err != nil || int64(len(line)+1) > s.segmentBytes {
		return errors.New("event record exceeds segment bound")
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.file == nil {
		return errors.New("event storage is closed")
	}
	if s.bytes+int64(len(line)) > s.segmentBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	n, err := s.file.Write(line)
	s.bytes += int64(n)
	if err != nil || n != len(line) {
		return errors.New("write event storage failed")
	}
	return nil
}

// Sync bounds normal shutdown data loss without forcing a disk sync per event.
func (s *Store) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.file == nil {
		return nil
	}
	if s.file.Sync() != nil {
		return errors.New("sync event storage failed")
	}
	return nil
}

// Close flushes the current segment. It is safe to call more than once.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	defer s.lock.Close()
	if s.file == nil {
		return nil
	}
	if err := s.file.Sync(); err != nil {
		_ = s.file.Close()
		return errors.New("sync event storage failed")
	}
	if err := s.file.Close(); err != nil {
		return errors.New("close event storage failed")
	}
	return nil
}
