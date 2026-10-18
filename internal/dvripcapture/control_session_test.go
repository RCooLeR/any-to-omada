package dvripcapture

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestControlSessionFactoryObjectAndSequence(t *testing.T) {
	device, done := startFake(t, func(p fakePeer) error {
		if err := p.login(true); err != nil {
			return err
		}
		request, err := p.request("ptz.factory.instance")
		if err != nil {
			return err
		}
		body, err := json.Marshal(map[string]any{"id": request["id"], "result": 42})
		if err != nil {
			return err
		}
		if err := writeFrame(p, [32]byte{0: 0xf6}, body); err != nil {
			return err
		}
		request, err = p.request("ptz.stop")
		if err != nil {
			return err
		}
		if request["object"] != json.Number("42") || request["seq"] != json.Number("7") {
			return errors.New("session factory handle or command sequence missing")
		}
		if err := p.reply(request, nil, ""); err != nil {
			return err
		}
		request, err = p.request("ptz.stop")
		if err != nil {
			return err
		}
		if request["object"] != json.Number("42") || request["seq"] != json.Number("31496") {
			return errors.New("session-derived command sequence missing")
		}
		if err := p.reply(request, nil, ""); err != nil {
			return err
		}
		request, err = p.request("global.logout")
		if err != nil {
			return err
		}
		if _, present := request["seq"]; present {
			return errors.New("sequence incorrectly added to logout")
		}
		return p.reply(request, nil, "")
	})
	err := ControlSession(t.Context(), device, func(call ControlCall) error {
		answer, err := call(t.Context(), ControlRequest{Method: "ptz.factory.instance", Params: map[string]any{"channel": 0}})
		if err != nil {
			return err
		}
		if answer["result"] != json.Number("42") {
			return errors.New("factory result lost")
		}
		_, err = call(context.Background(), ControlRequest{Method: "ptz.stop", Params: map[string]any{"code": "Right", "channel": 0}, Object: 42, Sequence: 7})
		if err != nil {
			return err
		}
		_, err = call(context.Background(), ControlRequest{Method: "ptz.stop", Params: map[string]any{"code": "Right", "channel": 0}, Object: 42, Sequence: 8, SessionSequence: true})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
