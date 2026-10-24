package schematest

import (
	"strings"
	"testing"
)

// fixtureSchema exercises every keyword the validator supports, so each case
// below can break exactly one of them.
const fixtureSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.invalid/fixture.json",
  "title": "fixture",
  "description": "every supported keyword",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "when"],
  "properties": {
    "version": {"const": 1},
    "when": {"type": "string", "format": "date-time"},
    "kind": {"type": "string", "enum": ["a", "b"]},
    "count": {"type": "integer", "minimum": 0, "maximum": 10},
    "ratio": {"type": "number"},
    "flag": {"type": "boolean"},
    "items": {"type": "array", "items": {"$ref": "#/$defs/item"}},
    "untyped": {"type": "array"},
    "map": {"type": "object", "additionalProperties": {"type": "integer"}},
    "open": {"type": "object", "additionalProperties": true},
    "loose": {"type": "object"},
    "label": {"const": "fixed"}
  },
  "$defs": {
    "item": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}
  }
}`

func TestValidateAcceptsAConformingDocument(t *testing.T) {
	document := `{"version": 1, "when": "2026-01-02T03:04:05.000Z", "kind": "a", "count": 10, "ratio": 0.5,
		"flag": true, "items": [{"name": "x"}], "untyped": [1, "two"], "map": {"x": 1}, "open": {"any": "thing"},
		"loose": {"any": 1}, "label": "fixed"}`
	if err := Validate([]byte(fixtureSchema), []byte(document)); err != nil {
		t.Fatal(err)
	}
	// 1.0 is an integer in JSON Schema, and an integer beyond int64 is still
	// one; neither may be refused for its spelling.
	for _, count := range []string{"1.0", "1e1"} {
		if err := Validate([]byte(`{"type": "integer"}`), []byte(count)); err != nil {
			t.Fatalf("%s: %v", count, err)
		}
	}
	if err := Validate([]byte(`{"type": "integer"}`), []byte("123456789012345678901234567890")); err != nil {
		t.Fatal(err)
	}
	// format describes strings only; any other value passes it.
	if err := Validate([]byte(`{"format": "date-time"}`), []byte("7")); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsEveryViolation(t *testing.T) {
	valid := `"version": 1, "when": "2026-01-02T03:04:05Z"`
	for _, testCase := range []struct {
		name, schema, document, want string
	}{
		{"schema not JSON", `[`, `{}`, "schema is not a JSON object"},
		{"document not JSON", fixtureSchema, `{`, "document is not JSON"},
		{"trailing data", fixtureSchema, `{` + valid + `} {}`, "data after its first JSON value"},
		{"unknown keyword", `{"type": "string", "pattern": "x", "minLength": 1}`, `"x"`, "unsupported keyword(s) minLength, pattern"},
		{"non-string reference", `{"$ref": 7}`, `1`, "unsupported schema reference 7"},
		{"foreign reference", `{"$ref": "other.json#/x"}`, `1`, "unsupported schema reference"},
		{"empty reference", `{"$ref": "#/$defs/"}`, `1`, "unsupported schema reference"},
		{"unknown definition", `{"$ref": "#/$defs/missing"}`, `1`, `unknown definition "#/$defs/missing"`},
		{"definition violated", fixtureSchema, `{` + valid + `, "items": [{"name": 1}]}`, "$.items[0].name has type json.Number, want string"},
		{"numeric const", fixtureSchema, `{"version": 2, "when": "2026-01-02T03:04:05Z"}`, "$.version = 2, want constant 1"},
		{"numeric const of a string", fixtureSchema, `{"version": "1", "when": "2026-01-02T03:04:05Z"}`, "want constant 1"},
		{"string const", fixtureSchema, `{` + valid + `, "label": "other"}`, "$.label = other, want constant fixed"},
		{"enum value", fixtureSchema, `{` + valid + `, "kind": "c"}`, "not in enum"},
		{"enum not an array", `{"enum": "a"}`, `"a"`, "enum is not an array"},
		{"below minimum", fixtureSchema, `{` + valid + `, "count": -1}`, "below minimum 0"},
		{"above maximum", fixtureSchema, `{` + valid + `, "count": 11}`, "above maximum 10"},
		{"bound not a number", `{"minimum": "0"}`, `1`, "minimum is not a number"},
		{"bound on a non-number", `{"maximum": 1}`, `"x"`, "maximum 1 needs a number"},
		{"unsupported format", `{"type": "string", "format": "email"}`, `"x"`, "unsupported format email"},
		{"bad date-time", fixtureSchema, `{"version": 1, "when": "yesterday"}`, `$.when = "yesterday" is not an RFC 3339 date-time`},
		{"not an object", fixtureSchema, `[]`, "want object"},
		{"required not an array", `{"type": "object", "required": "x"}`, `{}`, "required is not an array"},
		{"required not a string", `{"type": "object", "required": [1]}`, `{}`, "invalid required field 1"},
		{"missing required", fixtureSchema, `{"version": 1}`, `$ is missing required field "when"`},
		{"unexpected field", fixtureSchema, `{` + valid + `, "extra": 1}`, `$ has unexpected field "extra"`},
		{"additional schema violated", fixtureSchema, `{` + valid + `, "map": {"x": "one"}}`, "$.map.x = one, want integer"},
		{"additional not a schema", `{"type": "object", "additionalProperties": 1}`, `{"x": 1}`, "neither a boolean nor a schema"},
		{"not an array", fixtureSchema, `{` + valid + `, "items": {}}`, "want array"},
		{"items not a schema", `{"type": "array", "items": true}`, `[1]`, "items is not a schema"},
		{"not a string", `{"type": "string"}`, `1`, "want string"},
		{"not a boolean", fixtureSchema, `{` + valid + `, "flag": 1}`, "want boolean"},
		{"not an integer", fixtureSchema, `{` + valid + `, "count": 1.5}`, "$.count = 1.5, want integer"},
		{"integer of another type", `{"type": "integer"}`, `"1"`, "want integer"},
		{"not a number", fixtureSchema, `{` + valid + `, "ratio": "half"}`, "want number"},
		{"unsupported type", `{"type": ["string", "null"]}`, `"x"`, "unsupported schema type"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := Validate([]byte(testCase.schema), []byte(testCase.document))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to contain %q", err, testCase.want)
			}
		})
	}
}

// TestValidateNamesTheSameViolationEveryTime pins the sorted walk: with two
// bad fields the reported one must not depend on map iteration order.
func TestValidateNamesTheSameViolationEveryTime(t *testing.T) {
	document := `{"version": 1, "when": "2026-01-02T03:04:05Z", "zeta": 1, "alpha": 1}`
	for range 20 {
		err := Validate([]byte(fixtureSchema), []byte(document))
		if err == nil || !strings.Contains(err.Error(), `"alpha"`) {
			t.Fatalf("error = %v, want the alphabetically first unexpected field", err)
		}
	}
}
