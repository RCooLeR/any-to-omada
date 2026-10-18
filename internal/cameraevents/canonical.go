package cameraevents

// Brand-neutral codes. Adapters for sources other than Dahua DVRIP emit their
// detections in the CGI Code/Action form with these codes, so one normalizer
// and one Omada mapping serve every brand. They reuse the Dahua names the
// normalizer already understands; SmartMotionPet is the translator's own name
// for a pet or animal smart-motion detection, which Dahua does not report.
const (
	CodeMotion        = "VideoMotion"
	CodeHumanMotion   = "SmartMotionHuman"
	CodeVehicleMotion = "SmartMotionVehicle"
	CodePetMotion     = "SmartMotionPet"
	CodeLineCrossing  = "CrossLineDetection"
	CodeIntrusion     = "CrossRegionDetection"
	CodeTamper        = "VideoBlind"
)

// Canonical builds one notification in the CGI form Normalize accepts. Action
// is Start, Stop or Pulse; index is the source lens (-1 when unknown).
// Provenance names the native protocol and event type, for example
// "isapi:VMD", and keeps start and stop of one native event paired. Classes are
// human, vehicle or pet; rule identifies a native rule or region when known.
func Canonical(code, action string, index int, provenance string, classes []string, rule string) map[string]any {
	data := map[string]any{"event": provenance}
	if len(classes) > 0 {
		types := make([]any, 0, len(classes))
		for _, class := range classes {
			types = append(types, class)
		}
		data["ObjectTypes"] = types
	}
	if rule != "" {
		data["RuleID"] = rule
	}
	event := map[string]any{"Code": code, "Action": action, "Data": data}
	if index >= 0 {
		event["Index"] = index
	}
	return event
}
