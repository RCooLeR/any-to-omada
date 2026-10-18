package eventstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestartPreservesRecentPayloadsAndOnlyRetiresOwnedSegments(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "operator-note.txt"), []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		store, err := Open(directory, 4<<20, 2, []string{"super-secret"})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Write("camera", "native", "event", map[string]any{"Index": i, "password": "not-a-real-password", "nested": "rtsp://user:pass@example/stream", "text": "super-secret"}); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatal("retention did not retain exactly two segments plus unrelated file")
	}
	for _, entry := range entries {
		if !segmentName.MatchString(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "super-secret") || strings.Contains(string(data), "not-a-real-password") || strings.Contains(string(data), "user:pass") || !strings.Contains(string(data), "[redacted]") {
			t.Fatal("stored payload leaked credentials")
		}
	}
}

func TestSecondWriterIsRefusedAndCrashSafeOSLockIsReleased(t *testing.T) {
	directory := t.TempDir()
	first, err := Open(directory, 4<<20, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := Open(directory, 4<<20, 2, nil); err == nil {
		_ = second.Close()
		t.Fatal("second process writer accepted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(directory, 4<<20, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
}

func TestRotationNeverExceedsConfiguredSegmentSize(t *testing.T) {
	directory := t.TempDir()
	store, err := Open(directory, 4<<20, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	payload := map[string]string{"text": strings.Repeat("!", 200000)}
	for range 60 {
		if err := store.Write("camera", "native", "event", payload); err != nil {
			t.Fatal(err)
		}
	}
	files, err := store.owned()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatal("rotation did not bound segment count")
	}
	for _, name := range files {
		stat, err := os.Stat(filepath.Join(directory, name))
		if err != nil || stat.Size() > 4<<20 {
			t.Fatal("segment exceeded configured size")
		}
	}
}
