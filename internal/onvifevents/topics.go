package onvifevents

import (
	"strings"

	"github.com/RCooLeR/any-to-omada/internal/cameraevents"
)

// rule maps one ONVIF topic to a brand-neutral detection. Topics are matched
// after namespace prefixes are removed, so "tns1:RuleEngine/CellMotionDetector/Motion"
// and a vendor prefix compare equal; a topic ending in "/" matches every topic
// below it. The first matching rule wins.
type rule struct {
	topic string
	code  string
	// state names the boolean data item; none means an instantaneous pulse.
	state []string
	// byClass takes the code from the object class data items (human,
	// vehicle or pet smart motion).
	byClass bool
	// classState makes the detection active while class items are present;
	// an empty class list clears it (ONVIF ObjectDetection).
	classState bool
	// byItem treats each boolean data item as its own detection (Tapo, VIGI).
	byItem bool
	// trueOnly topics are sent only with "true" on some firmware; each one is
	// a pulse instead of an interval that would never end (Uniview).
	trueOnly bool
	// bySource names the source item whose value carries the class (Foscam).
	bySource string
}

// rules lists the documented ONVIF topics and the vendor topics confirmed in
// published integrations (Home Assistant onvif and onvif-parsers, reolink_aio,
// Kane610/axis). A topic missing here is journaled, never guessed.
var rules = []rule{
	{topic: "RuleEngine/CellMotionDetector/Motion", code: cameraevents.CodeMotion, state: []string{"IsMotion"}},
	{topic: "VideoSource/MotionAlarm", code: cameraevents.CodeMotion, state: []string{"State"}},
	{topic: "RuleEngine/MotionRegionDetector/Motion", code: cameraevents.CodeMotion, state: []string{"State", "IsMotion"}},
	{topic: "RuleEngine/FieldDetector/ObjectsInside", code: cameraevents.CodeIntrusion, state: []string{"IsInside"}},
	{topic: "RuleEngine/LineDetector/Crossed", code: cameraevents.CodeLineCrossing},
	{topic: "RuleEngine/TamperDetector/Tamper", code: cameraevents.CodeTamper, state: []string{"IsTamper", "State"}},
	{topic: "VideoSource/GlobalSceneChange/", code: cameraevents.CodeTamper, state: []string{"State"}},
	{topic: "RuleEngine/ObjectDetection/Object", byClass: true, classState: true},
	// Reolink smart detections.
	{topic: "RuleEngine/MyRuleDetector/PeopleDetect", code: cameraevents.CodeHumanMotion, state: []string{"State"}},
	{topic: "RuleEngine/MyRuleDetector/VehicleDetect", code: cameraevents.CodeVehicleMotion, state: []string{"State"}},
	{topic: "RuleEngine/MyRuleDetector/DogCatDetect", code: cameraevents.CodePetMotion, state: []string{"State"}},
	// TP-Link Tapo and VIGI: the data item names the detection.
	{topic: "RuleEngine/PeopleDetector/", byItem: true},
	{topic: "RuleEngine/TPSmartEventDetector/", byItem: true},
	{topic: "RuleEngine/CellMotionDetector/", byItem: true},
	{topic: "RuleEngine/LineCrossDetector/", byItem: true},
	// Uniview human shape detection.
	{topic: "UserAlarm/IVA/HumanShapeDetect", code: cameraevents.CodeHumanMotion, state: []string{"State"}, trueOnly: true},
	// Hanwha: legacy motion, WiseAI and generic object detectors with a class item.
	{topic: "VideoAnalytics/MotionDetection", code: cameraevents.CodeMotion, state: []string{"Motion", "State"}},
	{topic: "OpenApp/WiseAI/ObjectDetection", state: []string{"State"}, byClass: true},
	{topic: "RuleEngine/ObjectDetector/Object", state: []string{"State", "IsInside", "IsMotion"}, byClass: true},
	// Axis: VMD4/VMD3 profiles, Object Analytics scenarios, PIR and tampering.
	{topic: "CameraApplicationPlatform/VMD/", code: cameraevents.CodeMotion, state: []string{"active"}},
	{topic: "RuleEngine/VMD3/", code: cameraevents.CodeMotion, state: []string{"active"}},
	{topic: "CameraApplicationPlatform/ObjectAnalytics/", state: []string{"active"}, byClass: true},
	{topic: "Device/Sensor/PIR", code: cameraevents.CodeMotion, state: []string{"state"}},
	{topic: "VideoSource/Tampering", code: cameraevents.CodeTamper},
	// Foscam names the alarm in the VideoSource item; Vivotek reports a level.
	{topic: "Device/Trigger/MotionDetector", code: cameraevents.CodeMotion, state: []string{"State"}, bySource: "VideoSource"},
	{topic: "VideoAnalytics/Motion", code: cameraevents.CodeMotion, state: []string{"Level", "State"}},
}

// basenames match smart topics some firmware publishes under another parent.
var basenames = map[string]string{"PeopleDetect": "RuleEngine/MyRuleDetector/PeopleDetect",
	"VehicleDetect": "RuleEngine/MyRuleDetector/VehicleDetect", "DogCatDetect": "RuleEngine/MyRuleDetector/DogCatDetect"}

// itemCodes are the Tapo/VIGI data items and their detections.
var itemCodes = map[string]string{"IsMotion": cameraevents.CodeMotion, "IsPeople": cameraevents.CodeHumanMotion,
	"IsVehicle": cameraevents.CodeVehicleMotion, "IsPet": cameraevents.CodePetMotion, "IsLineCross": cameraevents.CodeLineCrossing,
	"IsIntrusion": cameraevents.CodeIntrusion, "IsTamper": cameraevents.CodeTamper}

var classCodes = map[string]string{"human": cameraevents.CodeHumanMotion, "vehicle": cameraevents.CodeVehicleMotion, "pet": cameraevents.CodePetMotion}

// stripTopic removes namespace prefixes from every topic segment.
func stripTopic(topic string) string {
	parts := strings.Split(strings.TrimSpace(topic), "/")
	for i, part := range parts {
		if _, local, found := strings.Cut(part, ":"); found {
			parts[i] = local
		}
	}
	return strings.Join(parts, "/")
}

// findRule selects the first matching exact or prefix topic rule, then checks explicitly
// recognized vendor basenames.
func findRule(topic string) (rule, bool) {
	topic = stripTopic(topic)
	for _, candidate := range rules {
		if strings.EqualFold(candidate.topic, topic) ||
			(strings.HasSuffix(candidate.topic, "/") && len(topic) > len(candidate.topic) && strings.EqualFold(candidate.topic, topic[:len(candidate.topic)])) {
			return candidate, true
		}
	}
	if full, ok := basenames[topic[strings.LastIndex(topic, "/")+1:]]; ok {
		return findRule(full)
	}
	return rule{}, false
}

// objectClass maps an ONVIF or vendor object class label to a translator class.
// "Vehical" is the misspelling in the legacy ONVIF metadata enumeration.
func objectClass(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "human", "people", "person", "face":
		return "human"
	case "vehicle", "vehical", "car", "bike", "bicycle", "motorcycle", "truck", "bus", "othervehicle", "licenseplate":
		return "vehicle"
	case "animal", "pet", "dog", "cat", "dogcat":
		return "pet"
	}
	return ""
}

// sourceClass reads a class from an alarm name such as HUMAN_DETECTION_ALARM.
func sourceClass(value string) string {
	// Alarm names are underscore-separated identifiers. Match whole class
	// tokens so an unrelated CARD alarm cannot become a CAR detection.
	for _, token := range strings.FieldsFunc(strings.ToUpper(value), func(r rune) bool {
		return r < 'A' || r > 'Z'
	}) {
		switch token {
		case "HUMAN", "PEOPLE":
			return "human"
		case "VEHICLE", "CAR":
			return "vehicle"
		case "PET", "ANIMAL":
			return "pet"
		}
	}
	return ""
}

// item reads a data item by name, ignoring case (Axis uses lower case).
func item(items map[string]string, name string) (string, bool) {
	if value, ok := items[name]; ok {
		return value, true
	}
	for key, value := range items {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

// classes reads object classes from the data items vendors use.
func classes(items map[string]string) []string {
	seen := map[string]bool{}
	var result []string
	for _, name := range []string{"ObjectType", "ClassTypes", "ClassType", "Type"} {
		value, _ := item(items, name)
		for _, label := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			if class := objectClass(label); class != "" && !seen[class] {
				seen[class] = true
				result = append(result, class)
			}
		}
	}
	return result
}

// boolValue accepts the boolean spellings cameras use, including Vivotek's
// motion level ("Trigger" or "Normal").
func boolValue(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "on", "active", "trigger":
		return true, true
	case "false", "0", "off", "inactive", "normal":
		return false, true
	}
	return false, false
}
