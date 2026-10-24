// Package schematest checks JSON documents against the published SpeeDNS
// schemas in tests. It is test support: no production code imports it, and it
// lives outside a _test.go file only so that the tests of the report and
// compare packages and of cmd/speedns can share one validator instead of each
// keeping a copy that drifts.
//
// It implements the subset of JSON Schema 2020-12 that schema/report-v1.json
// and schema/compare-v1.json use, and it rejects any other keyword instead of
// ignoring it, as scripts/testdata/validate-json-schema.py does. A validator
// that skipped a keyword it did not know would let a schema grow a constraint
// no test enforces while every contract test stayed green.
package schematest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"
)

// annotations carry no assertion, so they are accepted and never evaluated.
var annotations = map[string]bool{"$schema": true, "$id": true, "$defs": true, "title": true, "description": true}

// keywords are the assertions this validator enforces.
var keywords = map[string]bool{
	"$ref": true, "type": true, "const": true, "enum": true, "required": true, "properties": true,
	"additionalProperties": true, "items": true, "minimum": true, "maximum": true, "format": true,
}

const definitionPrefix = "#/$defs/"

// Validate reports whether document, a JSON value, conforms to schemaJSON.
// Numbers are decoded exactly, so an integer above 2^53 is checked as the
// integer the encoder wrote rather than as its nearest float64.
func Validate(schemaJSON, document []byte) error {
	var root map[string]any
	if err := json.Unmarshal(schemaJSON, &root); err != nil {
		return fmt.Errorf("schema is not a JSON object: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var instance any
	if err := decoder.Decode(&instance); err != nil {
		return fmt.Errorf("document is not JSON: %w", err)
	}
	if decoder.More() {
		return fmt.Errorf("document has data after its first JSON value")
	}
	return validate(root, instance, root, "$")
}

func validate(node map[string]any, instance any, root map[string]any, path string) error {
	if err := rejectUnknownKeywords(node, path); err != nil {
		return err
	}
	if reference, ok := node["$ref"]; ok {
		definition, err := resolve(reference, root, path)
		if err != nil {
			return err
		}
		if err := validate(definition, instance, root, path); err != nil {
			return err
		}
	}
	if expected, ok := node["const"]; ok && !sameValue(expected, instance) {
		return fmt.Errorf("%s = %v, want constant %v", path, instance, expected)
	}
	if enum, ok := node["enum"]; ok {
		if err := checkEnum(enum, instance, path); err != nil {
			return err
		}
	}
	if err := checkBounds(node, instance, path); err != nil {
		return err
	}
	if format, ok := node["format"]; ok {
		if err := checkFormat(format, instance, path); err != nil {
			return err
		}
	}
	schemaType, ok := node["type"]
	if !ok {
		return nil
	}
	switch schemaType {
	case "object":
		object, ok := instance.(map[string]any)
		if !ok {
			return fmt.Errorf("%s has type %T, want object", path, instance)
		}
		return validateObject(node, object, root, path)
	case "array":
		array, ok := instance.([]any)
		if !ok {
			return fmt.Errorf("%s has type %T, want array", path, instance)
		}
		return validateArray(node, array, root, path)
	case "string":
		if _, ok := instance.(string); !ok {
			return fmt.Errorf("%s has type %T, want string", path, instance)
		}
	case "boolean":
		if _, ok := instance.(bool); !ok {
			return fmt.Errorf("%s has type %T, want boolean", path, instance)
		}
	case "integer":
		if number, ok := instance.(json.Number); !ok || !isInteger(number) {
			return fmt.Errorf("%s = %v, want integer", path, instance)
		}
	case "number":
		if _, ok := instance.(json.Number); !ok {
			return fmt.Errorf("%s has type %T, want number", path, instance)
		}
	default:
		return fmt.Errorf("%s uses unsupported schema type %v", path, schemaType)
	}
	return nil
}

func rejectUnknownKeywords(node map[string]any, path string) error {
	unknown := make([]string, 0)
	for keyword := range node {
		if !annotations[keyword] && !keywords[keyword] {
			unknown = append(unknown, keyword)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%s schema uses unsupported keyword(s) %s", path, strings.Join(unknown, ", "))
}

func resolve(reference any, root map[string]any, path string) (map[string]any, error) {
	name, ok := reference.(string)
	if !ok || !strings.HasPrefix(name, definitionPrefix) || len(name) == len(definitionPrefix) {
		return nil, fmt.Errorf("%s uses unsupported schema reference %v", path, reference)
	}
	definitions, _ := root["$defs"].(map[string]any)
	definition, ok := definitions[strings.TrimPrefix(name, definitionPrefix)].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s references unknown definition %q", path, name)
	}
	return definition, nil
}

func checkEnum(enum any, instance any, path string) error {
	values, ok := enum.([]any)
	if !ok {
		return fmt.Errorf("%s schema enum is not an array", path)
	}
	for _, candidate := range values {
		if sameValue(candidate, instance) {
			return nil
		}
	}
	return fmt.Errorf("%s = %v, not in enum %v", path, instance, values)
}

func checkBounds(node map[string]any, instance any, path string) error {
	for _, bound := range []struct {
		keyword string
		breaks  func(value, limit float64) bool
		message string
	}{
		{"minimum", func(value, limit float64) bool { return value < limit }, "below minimum"},
		{"maximum", func(value, limit float64) bool { return value > limit }, "above maximum"},
	} {
		limitValue, present := node[bound.keyword]
		if !present {
			continue
		}
		limit, ok := limitValue.(float64)
		if !ok {
			return fmt.Errorf("%s schema %s is not a number", path, bound.keyword)
		}
		number, ok := instance.(json.Number)
		if !ok {
			return fmt.Errorf("%s = %v, %s %v needs a number", path, instance, bound.keyword, limit)
		}
		value, _ := number.Float64()
		if bound.breaks(value, limit) {
			return fmt.Errorf("%s = %v, %s %v", path, instance, bound.message, limit)
		}
	}
	return nil
}

// checkFormat enforces date-time, the only format the schemas use. Like the
// repository's Python validator it treats format as an assertion, so a
// timestamp the encoder renders wrongly fails here rather than in a consumer.
func checkFormat(format any, instance any, path string) error {
	if format != "date-time" {
		return fmt.Errorf("%s uses unsupported format %v", path, format)
	}
	text, ok := instance.(string)
	if !ok {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, text); err != nil {
		return fmt.Errorf("%s = %q is not an RFC 3339 date-time", path, text)
	}
	return nil
}

func validateObject(node map[string]any, object map[string]any, root map[string]any, path string) error {
	if required, ok := node["required"]; ok {
		names, ok := required.([]any)
		if !ok {
			return fmt.Errorf("%s schema required is not an array", path)
		}
		for _, field := range names {
			name, ok := field.(string)
			if !ok {
				return fmt.Errorf("%s has invalid required field %v", path, field)
			}
			if _, exists := object[name]; !exists {
				return fmt.Errorf("%s is missing required field %q", path, name)
			}
		}
	}
	properties, _ := node["properties"].(map[string]any)
	additional, hasAdditional := node["additionalProperties"]
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	// Sorted, so a document with two violations always names the same one.
	sort.Strings(names)
	for _, name := range names {
		value := object[name]
		if property, exists := properties[name].(map[string]any); exists {
			if err := validate(property, value, root, path+"."+name); err != nil {
				return err
			}
			continue
		}
		switch additional := additional.(type) {
		case bool:
			if !additional {
				return fmt.Errorf("%s has unexpected field %q", path, name)
			}
		case map[string]any:
			if err := validate(additional, value, root, path+"."+name); err != nil {
				return err
			}
		default:
			if hasAdditional {
				return fmt.Errorf("%s schema additionalProperties is neither a boolean nor a schema", path)
			}
		}
	}
	return nil
}

func validateArray(node map[string]any, array []any, root map[string]any, path string) error {
	items, ok := node["items"]
	if !ok {
		return nil
	}
	schema, ok := items.(map[string]any)
	if !ok {
		return fmt.Errorf("%s schema items is not a schema", path)
	}
	for index, value := range array {
		if err := validate(schema, value, root, fmt.Sprintf("%s[%d]", path, index)); err != nil {
			return err
		}
	}
	return nil
}

// sameValue compares a schema literal, decoded as float64, with an instance
// value, decoded as json.Number, numerically; everything else must be equal.
func sameValue(expected, instance any) bool {
	if number, ok := instance.(json.Number); ok {
		limit, isNumber := expected.(float64)
		value, err := number.Float64()
		return isNumber && err == nil && value == limit
	}
	return reflect.DeepEqual(expected, instance)
}

func isInteger(number json.Number) bool {
	if _, err := number.Int64(); err == nil {
		return true
	}
	value, err := number.Float64()
	return err == nil && math.Trunc(value) == value
}
