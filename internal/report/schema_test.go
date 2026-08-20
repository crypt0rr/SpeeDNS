package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/schema"
	"time"
)

func TestJSONReportsMatchPublishedSchema(t *testing.T) {
	var schemaDocument map[string]any
	if err := json.Unmarshal(schema.ReportV1(), &schemaDocument); err != nil {
		t.Fatal(err)
	}
	run := completeReport()
	run.Provenance = &benchmark.RunProvenance{
		Version: "dev", Commit: "unknown", BuildDate: "unknown", OS: "linux", Architecture: "amd64",
		Interfaces: []string{"lo"}, Protocols: []catalog.Protocol{catalog.UDP}, CorpusEntries: 1,
		CorpusSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Timeout:      time.Second, Concurrency: 1,
	}
	cases := []struct {
		name    string
		write   func(*bytes.Buffer) error
		wantRaw bool
	}{
		{name: "normal", write: func(output *bytes.Buffer) error { return WriteJSON(output, run, false) }},
		{name: "raw", write: func(output *bytes.Buffer) error { return WriteJSON(output, run, true) }, wantRaw: true},
		{name: "profile view", write: func(output *bytes.Buffer) error {
			return WriteJSONWithOptions(output, run, true, JSONOptions{ProfileView: true})
		}, wantRaw: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := tc.write(&output); err != nil {
				t.Fatal(err)
			}
			var instance any
			decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
			decoder.UseNumber()
			if err := decoder.Decode(&instance); err != nil {
				t.Fatal(err)
			}
			if err := validateJSONSchema(schemaDocument, instance, schemaDocument, "$"); err != nil {
				t.Fatalf("JSON does not match schema: %v\n%s", err, output.String())
			}
			if tc.wantRaw && !bytes.Contains(output.Bytes(), []byte(`"samples"`)) {
				t.Fatal("raw report did not include samples")
			}
		})
	}
}

func validateJSONSchema(document map[string]any, instance any, root map[string]any, path string) error {
	if reference, ok := document["$ref"].(string); ok {
		const prefix = "#/$defs/"
		if len(reference) <= len(prefix) || reference[:len(prefix)] != prefix {
			return fmt.Errorf("%s uses unsupported schema reference %q", path, reference)
		}
		name := reference[len(prefix):]
		definitions, ok := root["$defs"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s cannot resolve %q", path, reference)
		}
		definition, ok := definitions[name].(map[string]any)
		if !ok {
			return fmt.Errorf("%s references unknown definition %q", path, name)
		}
		return validateJSONSchema(definition, instance, root, path)
	}
	if expected, ok := document["const"]; ok {
		if expectedNumber, expectedIsNumber := numberValue(expected); expectedIsNumber {
			actualNumber, actualIsNumber := numberValue(instance)
			if !actualIsNumber || actualNumber != expectedNumber {
				return fmt.Errorf("%s = %v, want constant %v", path, instance, expected)
			}
		} else if !reflect.DeepEqual(expected, instance) {
			return fmt.Errorf("%s = %v, want constant %v", path, instance, expected)
		}
	}
	if enum, ok := document["enum"].([]any); ok {
		matched := false
		for _, candidate := range enum {
			if reflect.DeepEqual(candidate, instance) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s = %v, not in enum %v", path, instance, enum)
		}
	}
	if minimum, ok := numberValue(document["minimum"]); ok {
		value, valid := numberValue(instance)
		if !valid || value < minimum {
			return fmt.Errorf("%s = %v, below minimum %v", path, instance, minimum)
		}
	}
	if maximum, ok := numberValue(document["maximum"]); ok {
		value, valid := numberValue(instance)
		if !valid || value > maximum {
			return fmt.Errorf("%s = %v, above maximum %v", path, instance, maximum)
		}
	}

	schemaType, hasType := document["type"]
	if !hasType {
		return nil
	}
	switch schemaType {
	case "object":
		object, ok := instance.(map[string]any)
		if !ok {
			return fmt.Errorf("%s has type %T, want object", path, instance)
		}
		if required, ok := document["required"].([]any); ok {
			for _, field := range required {
				name, ok := field.(string)
				if !ok {
					return fmt.Errorf("%s has invalid required field %v", path, field)
				}
				if _, exists := object[name]; !exists {
					return fmt.Errorf("%s is missing required field %q", path, name)
				}
			}
		}
		properties, _ := document["properties"].(map[string]any)
		additional, hasAdditional := document["additionalProperties"]
		for name, value := range object {
			property, exists := properties[name].(map[string]any)
			if exists {
				if err := validateJSONSchema(property, value, root, path+"."+name); err != nil {
					return err
				}
				continue
			}
			if !hasAdditional || additional == true {
				continue
			}
			if additional == false {
				return fmt.Errorf("%s has unexpected field %q", path, name)
			}
			if property, ok := additional.(map[string]any); ok {
				if err := validateJSONSchema(property, value, root, path+"."+name); err != nil {
					return err
				}
			}
		}
	case "array":
		array, ok := instance.([]any)
		if !ok {
			return fmt.Errorf("%s has type %T, want array", path, instance)
		}
		if items, ok := document["items"].(map[string]any); ok {
			for index, value := range array {
				if err := validateJSONSchema(items, value, root, fmt.Sprintf("%s[%d]", path, index)); err != nil {
					return err
				}
			}
		}
	case "string":
		if _, ok := instance.(string); !ok {
			return fmt.Errorf("%s has type %T, want string", path, instance)
		}
	case "boolean":
		if _, ok := instance.(bool); !ok {
			return fmt.Errorf("%s has type %T, want boolean", path, instance)
		}
	case "integer":
		value, ok := numberValue(instance)
		if !ok || math.Trunc(value) != value {
			return fmt.Errorf("%s has value %v, want integer", path, instance)
		}
	case "number":
		if _, ok := numberValue(instance); !ok {
			return fmt.Errorf("%s has type %T, want number", path, instance)
		}
	default:
		return fmt.Errorf("%s uses unsupported schema type %v", path, schemaType)
	}
	return nil
}

func numberValue(value any) (float64, bool) {
	switch value := value.(type) {
	case json.Number:
		parsed, err := value.Float64()
		return parsed, err == nil
	case float64:
		return value, true
	case int:
		return float64(value), true
	default:
		return 0, false
	}
}
