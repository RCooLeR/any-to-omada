package app

import (
	"context"
	"reflect"
	"testing"

	"github.com/RCooLeR/any-to-omada/internal/config"
)

func TestSourceDisconnectClosesOnlyItsEnabledVirtualLenses(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	store := &memorySink{}
	s := newSource(config.Source{ID: "dual", Enabled: true}, "", []config.Camera{
		{ID: "ptz", SourceID: "dual", SourceIndex: 0, Enabled: true},
		{ID: "fixed", SourceID: "dual", SourceIndex: 1, Enabled: true},
		{ID: "disabled", SourceID: "dual", SourceIndex: 2, Enabled: false},
		{ID: "other-source", SourceID: "different", SourceIndex: 0, Enabled: true},
	}, store, cancel)
	called := map[string]int{}
	s.disconnected = func(id string) { called[id]++ }
	before := s.snapshot()
	s.endGeneration()
	if !reflect.DeepEqual(called, map[string]int{"ptz": 1, "fixed": 1}) {
		t.Fatalf("source disconnect crossed camera boundaries: %v", called)
	}
	if !reflect.DeepEqual(before, s.snapshot()) || len(store.records) != 0 || ctx.Err() != nil {
		t.Fatal("alarm reset mutated source state, wrote payloads, or cancelled capture")
	}
	// A second generation must retain the same routing without accumulating
	// hooks or including disabled cameras.
	s.startGeneration()
	s.endGeneration()
	if !reflect.DeepEqual(called, map[string]int{"ptz": 2, "fixed": 2}) {
		t.Fatal("source generation changed alarm reset routing")
	}
}

func TestSourceDisconnectWithoutCallbackOrLensHasNoSideEffects(t *testing.T) {
	s := &source{routes: map[int]string{0: "one"}}
	s.endGeneration()
	called := false
	s.routes = nil
	s.disconnected = func(string) { called = true }
	s.endGeneration()
	if called {
		t.Fatal("source without enabled virtual cameras invoked an alarm reset")
	}
}
