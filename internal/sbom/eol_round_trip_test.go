package sbom

import (
	"strings"
	"testing"
)

// componentNamed returns the one component in doc carrying name.
func componentNamed(t *testing.T, doc *Document, name string) Component {
	t.Helper()
	for _, component := range doc.Components {
		if component.Name == name {
			return component
		}
	}
	t.Fatalf("no component named %q in %+v", name, doc.Components)
	return Component{}
}

// Both formats wrote end-of-life fields that nothing ever read back, so a
// conversion silently dropped a claim the document plainly stated. Each
// format keeps exactly what it can write: SPDX has no cycle field in its
// package comment, CycloneDX does.
func TestEOLSurvivesADocumentRoundTrip(t *testing.T) {
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX16JSON} {
		t.Run(string(target), func(t *testing.T) {
			doc := &Document{
				Name: "eol",
				Components: []Component{{
					ID:      "pkg:npm/widget@1.0.0",
					Name:    "widget",
					Version: "1.0.0",
					PURL:    "pkg:npm/widget@1.0.0",
					EOL:     &EOL{EOL: true, EOLDate: "2025-01-31", Cycle: "1.x"},
				}},
			}
			raw, err := MarshalJSON(doc, target, EncodeOptions{Pretty: true})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			back, _, err := UnmarshalAutoJSON(raw)
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			got := componentNamed(t, back, "widget").EOL
			if got == nil {
				t.Fatalf("the end-of-life claim was dropped:\n%s", raw)
			}
			if !got.EOL {
				t.Errorf("eol flag = %v, want true", got.EOL)
			}
			if got.EOLDate != "2025-01-31" {
				t.Errorf("eol date = %q, want the source's", got.EOLDate)
			}
			if target == TargetCycloneDX16JSON && got.Cycle != "1.x" {
				t.Errorf("cycle = %q, want the source's -- CycloneDX carries it", got.Cycle)
			}
		})
	}
}

// A date without the flag is not a claim that anything is end-of-life, and an
// unparseable flag is not a reason to guess one.
func TestPartialOrMalformedEOLIsNotInvented(t *testing.T) {
	for _, testCase := range []struct{ name, comment string }{
		{"date without flag", "bomly:eol_date=2025-01-31"},
		{"unparseable flag", "bomly:eol=perhaps;eol_date=2025-01-31"},
		{"no eol fields", "bomly:scope=runtime"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := spdxCommentEOL(testCase.comment); got != nil {
				t.Errorf("invented an end-of-life record from %q: %+v", testCase.comment, got)
			}
		})
	}
}

// The property names are the wire format. A writer and reader that share a
// constant always agree with each other -- that is what the constant is for --
// but they can still agree on a name no other Bomly uses, which silently
// breaks every document already written. So the literals are pinned here, not
// compared to themselves.
func TestEOLPropertyNamesAreTheDocumentedWireNames(t *testing.T) {
	props := cycloneDXEOLProperties(&EOL{EOL: true, EOLDate: "2025-01-31", Cycle: "1.x"})
	if len(props) != 3 {
		t.Fatalf("properties = %+v, want flag, date and cycle", props)
	}
	got := cycloneDXIngestedEOL(&props)
	if got == nil || !got.EOL || got.EOLDate != "2025-01-31" || got.Cycle != "1.x" {
		t.Fatalf("reader did not recover what the writer emitted: %+v", got)
	}
	var names []string
	for _, p := range props {
		names = append(names, p.Name)
	}
	if joined := strings.Join(names, ","); joined != "bomly:eol,bomly:eol_date,bomly:eol_cycle" {
		t.Errorf("property names = %q, want the names the format documents", joined)
	}
}

// The same for SPDX, which carries the claim as comment fields rather than
// properties, and which has no cycle field to carry.
func TestSPDXEOLCommentFieldsAreTheDocumentedWireNames(t *testing.T) {
	comment := spdxPackageComment(Component{EOL: &EOL{EOL: true, EOLDate: "2025-01-31", Cycle: "1.x"}})
	for _, want := range []string{"eol=true", "eol_date=2025-01-31"} {
		if !strings.Contains(comment, want) {
			t.Errorf("package comment %q is missing %q", comment, want)
		}
	}
	if got := spdxCommentEOL(comment); got == nil || !got.EOL || got.EOLDate != "2025-01-31" {
		t.Errorf("reader did not recover what the writer emitted into %q: %+v", comment, got)
	}
}
