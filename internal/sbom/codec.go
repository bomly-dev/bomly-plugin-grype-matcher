package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// syftSchemaURLMarker is what makes a JSON document a syft-json one: syft
// stamps every document it writes with a schema.url pointing at its own
// schema, and every version of that URL contains "anchore/syft".
//
// Delegation was checked first and declined for one reason. The authority for
// this question is syft's own syftjson.NewFormatDecoder().Identify, which this
// replaces; the SDK owns no SBOM format recognition, and neither cyclonedx-go
// nor spdx/tools-golang can answer for a third format. But Identify is not a
// small library to borrow: importing it linked the whole anchore/syft tree --
// over a hundred packages of this package's closure, in both plugin repos --
// into a build that recognizes this format only to refuse it, and the codec
// carries no build tag, so the cost was paid unconditionally. The measured
// figures are in the pull request that made this change.
//
// What is reproduced here is the entirety of what Identify does: decode
// schema.url and test it for this substring. TestSyftSniffAgreesWithSyftsOwnIdentify
// is the guard -- it runs both against a fixture syft's own encoder produces,
// in the test build where importing syft costs nothing, so a syft release that
// moved the marker fails here instead of silently ingesting a format Bomly
// does not support.
const syftSchemaURLMarker = "anchore/syft"

var (
	ErrNilDocument       = errors.New("sbom document is nil")
	ErrUnsupportedTarget = errors.New("unsupported sbom target")
	ErrUnsupportedFormat = errors.New("unsupported sbom format")
	ErrMalformedJSON     = errors.New("malformed sbom json")

	// ErrSyftJSONUnsupported reports that the input is a syft-format JSON SBOM,
	// which Bomly no longer ingests. Detection is kept so callers can point the
	// user at the conversion path instead of a generic format error.
	ErrSyftJSONUnsupported = errors.New("syft JSON SBOMs are not supported; convert with: syft convert <file> -o spdx-json")
)

type codec interface {
	encodeJSON(doc *Document, opts EncodeOptions) ([]byte, error)
	decodeJSON(data []byte) (*Document, error)
}

var codecs = map[Target]codec{
	TargetSPDX23JSON:      spdx23Codec{},
	TargetCycloneDX14JSON: cycloneDXCodec{version: TargetCycloneDX14JSON},
	TargetCycloneDX15JSON: cycloneDXCodec{version: TargetCycloneDX15JSON},
	TargetCycloneDX16JSON: cycloneDXCodec{version: TargetCycloneDX16JSON},
	TargetCycloneDX17JSON: cycloneDXCodec{version: TargetCycloneDX17JSON},
}

// MarshalJSON renders the intermediate SBOM document to a target JSON format.
func MarshalJSON(doc *Document, target Target, opts EncodeOptions) ([]byte, error) {
	if doc == nil {
		return nil, ErrNilDocument
	}
	c, ok := codecs[target]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedTarget, target)
	}
	return c.encodeJSON(doc, opts)
}

// UnmarshalJSON parses a target JSON SBOM into the intermediate document model.
func UnmarshalJSON(data []byte, target Target) (*Document, error) {
	c, ok := codecs[target]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedTarget, target)
	}
	return c.decodeJSON(data)
}

// DetectJSONTarget identifies the supported SBOM JSON format represented by data.
func DetectJSONTarget(data []byte) (Target, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || !json.Valid(trimmed) {
		return "", ErrMalformedJSON
	}

	var sniff struct {
		SPDXVersion string `json:"spdxVersion"`
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Schema      struct {
			URL string `json:"url"`
		} `json:"schema"`
	}
	if err := json.Unmarshal(trimmed, &sniff); err != nil {
		return "", ErrMalformedJSON
	}

	if strings.Contains(sniff.Schema.URL, syftSchemaURLMarker) {
		return TargetSyftJSON, nil
	}

	switch {
	case sniff.SPDXVersion == "SPDX-2.3":
		return TargetSPDX23JSON, nil
	case sniff.BOMFormat == "CycloneDX":
		switch sniff.SpecVersion {
		case "1.4":
			return TargetCycloneDX14JSON, nil
		case "1.5":
			return TargetCycloneDX15JSON, nil
		case "1.6":
			return TargetCycloneDX16JSON, nil
		case "1.7":
			return TargetCycloneDX17JSON, nil
		}
		return "", ErrUnsupportedFormat
	}

	return "", ErrUnsupportedFormat
}

// UnmarshalAutoJSON parses a supported SBOM JSON payload without requiring the caller to preselect a target.
func UnmarshalAutoJSON(data []byte) (*Document, Target, error) {
	target, err := DetectJSONTarget(data)
	if err != nil {
		return nil, "", err
	}
	if target == TargetSyftJSON {
		return nil, target, ErrSyftJSONUnsupported
	}

	doc, err := UnmarshalJSON(data, target)
	if err != nil {
		return nil, "", err
	}
	return doc, target, nil
}

// MarshalDepGraphJSON converts a dependency graph directly into a target JSON SBOM.
func MarshalDepGraphJSON(g *sdk.Graph, target Target, buildOpts BuildOptions, encodeOpts EncodeOptions) ([]byte, error) {
	doc, err := FromDepGraph(g, buildOpts)
	if err != nil {
		return nil, err
	}
	return MarshalJSON(doc, target, encodeOpts)
}
