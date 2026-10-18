package app

import (
	"context"
	"errors"
	"testing"

	"github.com/RCooLeR/any-to-omada/internal/config"
)

// stored retains one source journal call for assertions about native and normalized output.
type stored struct {
	kind, protocol string
	data           any
}

// memorySink collects synchronous source writes and can inject a persistence failure.
type memorySink struct {
	records []stored
	failure error
}

// Write records the attempted journal entry before returning the configured storage error.
func (s *memorySink) Write(_ string, protocol, kind string, data any) error {
	s.records = append(s.records, stored{kind, protocol, data})
	return s.failure
}

func TestSharedPhysicalNotificationRoutesEachLensWithoutInventingClasses(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	store := &memorySink{}
	s := newSource(config.Source{ID: "dual", Enabled: true}, "", []config.Camera{{ID: "ptz", SourceID: "dual", SourceIndex: 0, Enabled: true}, {ID: "fixed", SourceID: "dual", SourceIndex: 1, Enabled: true}, {ID: "other-source", SourceID: "different", SourceIndex: 0, Enabled: true}}, store, cancel)
	payload := `{"method":"client.notifyEventStream","params":{"eventList":[{"Code":"Intelligent","Action":"Start","Index":0,"Data":{"event":336700,"UTC":1770000001}},{"Code":"SmartMotionHuman","Action":"Stop","Index":1,"Data":{"UTC":1770000002}},{"Code":"VideoMotion","Action":"Start","Data":{}}]}}`
	if err := s.Write("dual", "dvrip", "event", payload); err != nil {
		t.Fatal(err)
	}
	if len(store.records) != 4 {
		t.Fatalf("expected one raw record and three normalized edges, got %d", len(store.records))
	}
	first := store.records[1].data.(routedEvent)
	second := store.records[2].data.(routedEvent)
	third := store.records[3].data.(routedEvent)
	if first.VirtualCameraID != "ptz" || second.VirtualCameraID != "fixed" || third.VirtualCameraID != "" {
		t.Fatal("event crossed lens/source identity boundary")
	}
	if first.Event.Class != "unknown" || second.Event.Class != "human" || first.Event.DeviceUTC.String() != "1770000001" || second.Event.Action != "Stop" || first.Delivery != "unsupported" {
		t.Fatal("classification, timing or unsupported-delivery provenance lost")
	}
	status := s.snapshot()
	if status.Notifications != 1 || status.Normalized != 3 || status.Unrouted != 1 || status.LensEdges["ptz"] != 1 || status.LensEdges["fixed"] != 1 || ctx.Err() != nil {
		t.Fatal("shared source counters incorrect")
	}
}

func TestPersistenceFailureCancelsDaemonAndWrongSourceIsRejected(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	s := newSource(config.Source{ID: "one"}, "", nil, &memorySink{failure: errors.New("disk full")}, cancel)
	if s.Write("other", "dvrip", "heartbeat", nil) == nil {
		t.Fatal("foreign source accepted")
	}
	if ctx.Err() != nil {
		t.Fatal("foreign identity should not write")
	}
	if s.Write("one", "dvrip", "heartbeat", nil) == nil || ctx.Err() == nil {
		t.Fatal("storage failure did not stop capture")
	}
}
