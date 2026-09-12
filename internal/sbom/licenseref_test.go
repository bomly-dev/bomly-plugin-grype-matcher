package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// licenseGraph builds a one-package graph whose licenses a case chooses.
func licenseGraph(t *testing.T, licenses ...sdk.PackageLicense) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	pkg := testkit.MustDependencyNode(t, "pkg:npm/widget@1.0.0")
	sdk.SetDetectionLicenses(pkg, licenses)
	if err := g.AddNode(pkg); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return g
}

// spdxDocOf marshals a graph to SPDX and decodes the raw document, so a test
// can assert on the fields SPDX defines rather than on our model.
func spdxDocOf(t *testing.T, g *sdk.Graph) map[string]any {
	t.Helper()
	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	return doc
}

// SPDX 2.3 has no free-text license field: licenseDeclared must hold a valid
// expression, NOASSERTION, NONE, or a LicenseRef. Writing "see LICENSE file"
// verbatim produces a document a strict consumer can reject, and the lite
// build hands exactly that document to an external tool.
func TestUnrecognizedLicenseBecomesAReferenceWithItsText(t *testing.T) {
	const raw = "see LICENSE file"
	doc := spdxDocOf(t, licenseGraph(t, sdk.PackageLicense{Value: raw}))

	packages, _ := doc["packages"].([]any)
	if len(packages) == 0 {
		t.Fatalf("no packages in document")
	}
	pkg, _ := packages[0].(map[string]any)
	declared, _ := pkg["licenseDeclared"].(string)

	want := spdxkit.MintLicenseRef(raw).RefID
	if declared != want {
		t.Fatalf("licenseDeclared = %q, want the minted reference %q", declared, want)
	}
	if declared == raw {
		t.Fatalf("the raw value reached licenseDeclared verbatim")
	}
	if !spdxkit.Valid(declared) {
		t.Fatalf("licenseDeclared %q does not parse as an SPDX expression", declared)
	}

	// And the text travels with it, which is what a reference is for.
	others, _ := doc["hasExtractedLicensingInfos"].([]any)
	if len(others) != 1 {
		t.Fatalf("hasExtractedLicensingInfos = %v, want one entry", others)
	}
	entry, _ := others[0].(map[string]any)
	if got, _ := entry["licenseId"].(string); got != want {
		t.Fatalf("extracted licenseId = %q, want %q", got, want)
	}
	if got, _ := entry["extractedText"].(string); got != raw {
		t.Fatalf("extractedText = %q, want the original %q", got, raw)
	}
}

// Every license field this codec writes has to satisfy the format, not just
// the declared one: the codec writes the same value into licenseConcluded,
// and a consumer validating the document reads both.
func TestEveryEmittedLicenseFieldIsAValidSPDXExpression(t *testing.T) {
	doc := spdxDocOf(t, licenseGraph(t, sdk.PackageLicense{Value: "see LICENSE file"}))
	packages, _ := doc["packages"].([]any)
	if len(packages) == 0 {
		t.Fatalf("no packages in document")
	}
	pkg, _ := packages[0].(map[string]any)
	for _, field := range []string{"licenseDeclared", "licenseConcluded"} {
		value, _ := pkg[field].(string)
		if value == "" || value == "NOASSERTION" || value == "NONE" {
			continue
		}
		if !spdxkit.Valid(value) {
			t.Fatalf("%s = %q does not parse as an SPDX expression", field, value)
		}
	}
}

// A recognized license is untouched: the reference machinery applies only
// where SPDX cannot hold the value.
func TestRecognizedLicenseMintsNoReference(t *testing.T) {
	doc := spdxDocOf(t, licenseGraph(t, sdk.PackageLicense{SPDXExpression: "Apache-2.0"}))
	packages, _ := doc["packages"].([]any)
	pkg, _ := packages[0].(map[string]any)
	if declared, _ := pkg["licenseDeclared"].(string); declared != "Apache-2.0" {
		t.Fatalf("licenseDeclared = %q, want %q", declared, "Apache-2.0")
	}
	if _, present := doc["hasExtractedLicensingInfos"]; present {
		t.Fatalf("a recognized license produced an extracted-text section")
	}
}

// A set of one recognized and one unrecognized license composes whole. A
// reference is a valid expression element, so nothing a source declared has
// to be dropped to keep the field parseable.
func TestMixedLicenseSetComposesRatherThanDropping(t *testing.T) {
	const raw = "see LICENSE file"
	doc := spdxDocOf(t, licenseGraph(t,
		sdk.PackageLicense{SPDXExpression: "MIT"},
		sdk.PackageLicense{Value: raw},
	))
	packages, _ := doc["packages"].([]any)
	pkg, _ := packages[0].(map[string]any)
	declared, _ := pkg["licenseDeclared"].(string)

	ref := spdxkit.MintLicenseRef(raw).RefID
	if !strings.Contains(declared, "MIT") || !strings.Contains(declared, ref) {
		t.Fatalf("licenseDeclared = %q, want both MIT and %q", declared, ref)
	}
	if !spdxkit.Valid(declared) {
		t.Fatalf("composed licenseDeclared %q does not parse", declared)
	}
}

// Two components carrying the same unrecognized text mint the same reference
// and collapse to one entry. That is what makes the identifier safe to share
// across a document assembled from independent sources.
func TestIdenticalTextsShareOneReference(t *testing.T) {
	const raw = "internal use only"
	g := sdk.New()
	for _, name := range []string{"alpha", "beta"} {
		pkg := testkit.MustDependencyNode(t, "pkg:npm/"+name+"@1.0.0")
		sdk.SetDetectionLicenses(pkg, []sdk.PackageLicense{{Value: raw}})
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add node(%s): %v", name, err)
		}
	}
	doc := spdxDocOf(t, g)

	others, _ := doc["hasExtractedLicensingInfos"].([]any)
	if len(others) != 1 {
		t.Fatalf("hasExtractedLicensingInfos has %d entries, want one shared by both packages", len(others))
	}
	want := spdxkit.MintLicenseRef(raw).RefID
	packages, _ := doc["packages"].([]any)
	if len(packages) != 2 {
		t.Fatalf("packages = %d, want two", len(packages))
	}
	for _, p := range packages {
		pkg, _ := p.(map[string]any)
		if declared, _ := pkg["licenseDeclared"].(string); declared != want {
			t.Fatalf("package %v licenseDeclared = %q, want the shared reference %q", pkg["name"], declared, want)
		}
	}
}

// Round trip: ingesting the exported document recovers the original text.
// Without this the reference preserves nothing a reader can use -- it would
// return "LicenseRef-<hash>" where the source said "see LICENSE file".
func TestReferenceRoundTripRecoversTheOriginalText(t *testing.T) {
	const raw = "see LICENSE file"
	out, err := MarshalDepGraphJSON(licenseGraph(t, sdk.PackageLicense{Value: raw}),
		TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	ingested, err := UnmarshalJSON(out, TargetSPDX23JSON)
	if err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	var found bool
	for _, component := range ingested.Components {
		for _, license := range component.Licenses {
			if license.Value == raw {
				found = true
			}
			if license.Value == spdxkit.MintLicenseRef(raw).RefID {
				t.Fatalf("the reference survived as the license value; the text was not read back")
			}
		}
	}
	if !found {
		t.Fatalf("round trip lost the original license text %q: %+v", raw, ingested.Components)
	}
}

// A foreign document's own reference-to-text pairing is taken as stated. The
// kit's mint is the authority for values this process wrote; for a document
// written elsewhere the document is.
func TestForeignReferencePairingIsTakenAsStated(t *testing.T) {
	const foreign = `{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "foreign",
  "documentNamespace": "https://example.com/foreign",
  "creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: elsewhere"]},
  "hasExtractedLicensingInfos": [
    {"licenseId": "LicenseRef-vendor-1", "extractedText": "vendor terms v1"}
  ],
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-widget",
      "name": "widget",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseDeclared": "LicenseRef-vendor-1"
    }
  ]
}`
	doc, err := UnmarshalJSON([]byte(foreign), TargetSPDX23JSON)
	if err != nil {
		t.Fatalf("unmarshal foreign document: %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("components = %d, want one", len(doc.Components))
	}
	licenses := doc.Components[0].Licenses
	if len(licenses) != 1 {
		t.Fatalf("licenses = %+v, want one", licenses)
	}
	if licenses[0].Value != "vendor terms v1" {
		t.Fatalf("license value = %q, want the text the document stated", licenses[0].Value)
	}
	if licenses[0].SPDXExpression != "LicenseRef-vendor-1" {
		t.Fatalf("expression = %q, want the reference the document used", licenses[0].SPDXExpression)
	}
}
