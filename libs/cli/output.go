/*
FILE PATH: libs/cli/output.go

DESCRIPTION:

	The machine-output contract (PRE-1). Every read verb renders through ONE
	printer with two modes:

	  --output table   the human text (free to change between releases)
	  --output json    ONE versioned envelope on stdout:
	                     {"schema_version":"baseproof.cli/v1",
	                      "kind":"<verb>",
	                      "data":{...}}

	The envelope is a CONTRACT: schema_version only changes with a breaking
	data-shape change; kinds are per-verb; data shapes may gain fields but
	never repurpose them. stdout carries DATA ONLY — informational prints go
	to stderr (PRE-0b), so a JSON pipe is never corrupted.
*/
package cli

import (
	"encoding/json"
	"fmt"
	"os"
)

// EnvelopeSchemaVersion versions every --output json document.
const EnvelopeSchemaVersion = "baseproof.cli/v1"

// Envelope is the one machine-output wrapper.
type Envelope struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	Data          any    `json:"data"`
}

// emitOutput renders one verb's result: "json" emits the versioned envelope
// on stdout; "table" (or empty) runs the human renderer; anything else is a
// usage error.
func emitOutput(output, kind string, data any, table func() error) error {
	switch output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(Envelope{SchemaVersion: EnvelopeSchemaVersion, Kind: kind, Data: data}); err != nil {
			return fmt.Errorf("emit json: %w", err)
		}
		return nil
	case "", "table":
		return table()
	default:
		return fmt.Errorf("--output %q: want table|json", output)
	}
}

// tablef / tableln are the ONLY in-package stdout writers besides the JSON
// encoder above — every table renderer prints through them, so the guard
// test (pre1_stdout_guard_test.go) can enforce "no stdout writes outside
// output.go" mechanically instead of by review discipline.
func tablef(format string, a ...any) { fmt.Fprintf(os.Stdout, format, a...) }

func tableln(a ...any) { fmt.Fprintln(os.Stdout, a...) }

// stdout returns the data stream for writer-parameterized renderers
// (usage, renderNetwork, renderProof) — the licensed alternative to a
// direct os.Stdout reference outside this file.
func stdout() *os.File { return os.Stdout }
