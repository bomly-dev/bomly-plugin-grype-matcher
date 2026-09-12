package sbom

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

// The digest algorithm enumerations belong to the SDK's registry, which is
// built from spdx/tools-golang's and CycloneDX/cyclonedx-go's own constants.
// This package used to transcribe them, and the transcription was narrower
// than the specifications: a digest the SDK can name was dropped on export at
// the very gate that exists to reject unpublishable values.
//
// These tests pin the delegation. Every algorithm the SDK registers with a
// spelling for a format must survive that format's mapper, so reintroducing a
// hand-written table -- or an SDK bump that drops a member -- fails here
// rather than silently discarding digests at runtime.
func TestSPDXChecksumAlgorithmCoversTheSDKRegistry(t *testing.T) {
	for _, algorithm := range sdk.DigestAlgorithms() {
		name := algorithm.SPDXName()
		if name == "" {
			// SPDX genuinely has no member for it; dropping is correct.
			continue
		}
		if got := string(spdxChecksumAlgorithm(algorithm.String())); got != name {
			t.Errorf("spdxChecksumAlgorithm(%q) = %q, want %q", algorithm, got, name)
		}
	}
}

func TestCycloneDXHashAlgorithmCoversTheSDKRegistry(t *testing.T) {
	for _, algorithm := range sdk.DigestAlgorithms() {
		name := algorithm.CycloneDXName()
		if name == "" {
			// CycloneDX genuinely has no member for it; dropping is correct.
			continue
		}
		if got := string(cycloneDXHashAlgorithm(algorithm.String())); got != name {
			t.Errorf("cycloneDXHashAlgorithm(%q) = %q, want %q", algorithm, got, name)
		}
	}
}

// Both mappers accept the separator variants a real document uses, and reject
// what neither format defines.
func TestDigestAlgorithmSpellingsAndRejection(t *testing.T) {
	for _, spelling := range []string{"SHA-256", "sha256", "SHA256", " sha-256 "} {
		if got := string(spdxChecksumAlgorithm(spelling)); got != sdk.DigestAlgorithmSHA256.SPDXName() {
			t.Errorf("spdxChecksumAlgorithm(%q) = %q, want the SHA256 member", spelling, got)
		}
		if got := string(cycloneDXHashAlgorithm(spelling)); got != sdk.DigestAlgorithmSHA256.CycloneDXName() {
			t.Errorf("cycloneDXHashAlgorithm(%q) = %q, want the SHA256 member", spelling, got)
		}
	}
	for _, spelling := range []string{"", "   ", "not-an-algorithm", "sha255"} {
		if got := spdxChecksumAlgorithm(spelling); got != "" {
			t.Errorf("spdxChecksumAlgorithm(%q) = %q, want the digest dropped", spelling, got)
		}
		if got := cycloneDXHashAlgorithm(spelling); got != "" {
			t.Errorf("cycloneDXHashAlgorithm(%q) = %q, want the digest dropped", spelling, got)
		}
	}
}
