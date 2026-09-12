package sbom

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type spdx23Codec struct{}

func (spdx23Codec) encodeJSON(doc *Document, opts EncodeOptions) ([]byte, error) {
	idByComponent := make(map[string]common.ElementID, len(doc.Components))
	usedIDs := make(map[string]int, len(doc.Components))
	packages := make([]*v23.Package, 0, len(doc.Components))

	// Collected while packages render, emitted once as the document's
	// hasExtractedLicensingInfos: a reference is written per package but the
	// text it names lives at document scope.
	var extractedLicenses []spdxkit.ExtractedText

	for _, c := range doc.Components {
		base := sanitizeSPDXID(c.ID)
		seq := usedIDs[base]
		usedIDs[base] = seq + 1
		if seq > 0 {
			base = fmt.Sprintf("%s-%d", base, seq)
		}
		spdxID := common.ElementID(base)
		idByComponent[c.ID] = spdxID

		licenseValue, componentExtracted := spdxLicenseValue(c.Licenses)
		extractedLicenses = append(extractedLicenses, componentExtracted...)

		packages = append(packages, &v23.Package{
			PackageName:               c.NameOrID(),
			PackageSPDXIdentifier:     spdxID,
			PackageVersion:            c.Version,
			PackageDownloadLocation:   "NOASSERTION",
			FilesAnalyzed:             false,
			PackageComment:            spdxPackageComment(c),
			PackageLicenseDeclared:    licenseValue,
			PackageLicenseConcluded:   licenseValue,
			PackageCopyrightText:      spdxCopyrightValue(c.Copyright),
			PackageChecksums:          spdxChecksums(c.Digests),
			PackageExternalReferences: spdxExternalReferences(c),
		})
	}

	relationships := make([]*v23.Relationship, 0, len(doc.Dependencies)+len(doc.Roots))
	documentRef := common.DocElementID{ElementRefID: common.ElementID("DOCUMENT")}
	for _, root := range doc.Roots {
		rootID, ok := idByComponent[root]
		if !ok {
			continue
		}
		relationships = append(relationships, &v23.Relationship{
			RefA:         documentRef,
			RefB:         common.DocElementID{ElementRefID: rootID},
			Relationship: common.TypeRelationshipDescribe,
		})
	}

	for _, dep := range doc.Dependencies {
		fromID, ok := idByComponent[dep.Ref]
		if !ok {
			continue
		}
		for _, to := range dep.DependsOn {
			toID, ok := idByComponent[to]
			if !ok {
				continue
			}
			relationships = append(relationships, &v23.Relationship{
				RefA:         common.DocElementID{ElementRefID: fromID},
				RefB:         common.DocElementID{ElementRefID: toID},
				Relationship: common.TypeRelationshipDependsOn,
			})
		}
	}

	creators := make([]common.Creator, 0, len(doc.ToolNamesOrDefault()))
	for _, tool := range doc.ToolNamesOrDefault() {
		creators = append(creators, common.Creator{
			CreatorType: "Tool",
			Creator:     tool,
		})
	}
	creation := &v23.CreationInfo{
		Creators: creators,
		Created:  doc.CreatedOrNow().Format("2006-01-02T15:04:05Z"),
	}

	spdxDoc := &v23.Document{
		SPDXVersion:       v23.Version,
		DataLicense:       v23.DataLicense,
		SPDXIdentifier:    common.ElementID("DOCUMENT"),
		DocumentName:      doc.NameOrDefault(),
		DocumentNamespace: doc.NamespaceOrDefault(),
		CreationInfo:      creation,
		Packages:          packages,
		Relationships:     relationships,
		OtherLicenses:     spdxOtherLicenses(extractedLicenses),
	}

	return marshalJSON(spdxDoc, opts.Pretty)
}

func (spdx23Codec) decodeJSON(data []byte) (*Document, error) {
	var spdxDoc v23.Document
	if err := json.Unmarshal(data, &spdxDoc); err != nil {
		return nil, err
	}

	extractedByRef := spdxExtractedTexts(spdxDoc.OtherLicenses)

	components := make([]Component, 0, len(spdxDoc.Packages))
	for _, p := range spdxDoc.Packages {
		if p == nil {
			continue
		}
		id := common.RenderElementID(p.PackageSPDXIdentifier)
		components = append(components, Component{
			ID:             id,
			Name:           p.PackageName,
			Version:        p.PackageVersion,
			Scope:          parseSPDXCommentField(p.PackageComment, "scope"),
			Type:           parseSPDXComponentType(p),
			PURL:           parseSPDXPURL(p.PackageExternalReferences),
			Ecosystem:      parseSPDXEcosystem(p.PackageExternalReferences),
			PackageManager: parseSPDXPackageManager(p.PackageExternalReferences),
			Copyright:      parseSPDXCopyright(p.PackageCopyrightText),
			Licenses:       parseSPDXLicenses(extractedByRef, p.PackageLicenseConcluded, p.PackageLicenseDeclared),
			EOL:            spdxCommentEOL(p.PackageComment),
		})
	}

	depsByRef := make(map[string][]string, len(components))
	for _, c := range components {
		depsByRef[c.ID] = nil
	}

	roots := make([]string, 0)
	for _, rel := range spdxDoc.Relationships {
		if rel == nil {
			continue
		}
		a := common.RenderDocElementID(rel.RefA)
		b := common.RenderDocElementID(rel.RefB)

		switch rel.Relationship {
		case common.TypeRelationshipDescribe:
			if a == "SPDXRef-DOCUMENT" {
				roots = append(roots, b)
			}
		case common.TypeRelationshipDependsOn:
			depsByRef[a] = append(depsByRef[a], b)
		case common.TypeRelationshipDependencyOf,
			common.TypeRelationshipBuildDependencyOf,
			common.TypeRelationshipDevDependencyOf,
			common.TypeRelationshipOptionalDependencyOf,
			common.TypeRelationshipProvidedDependencyOf,
			common.TypeRelationshipRuntimeDependencyOf,
			common.TypeRelationshipTestDependencyOf:
			depsByRef[b] = append(depsByRef[b], a)
		}
	}

	dependencies := make([]Dependency, 0, len(components))
	for _, c := range components {
		deps := depsByRef[c.ID]
		if len(deps) > 1 {
			sort.Strings(deps)
		}
		dependencies = append(dependencies, Dependency{
			Ref:       c.ID,
			DependsOn: deps,
		})
	}

	sort.Slice(components, func(i, j int) bool { return components[i].ID < components[j].ID })
	sort.Strings(roots)

	return &Document{
		Name:         spdxDoc.DocumentName,
		Namespace:    spdxDoc.DocumentNamespace,
		Tool:         extractSPDXToolName(spdxDoc.CreationInfo),
		Tools:        extractSPDXToolNames(spdxDoc.CreationInfo),
		Created:      parseSPDXCreated(spdxDoc.CreationInfo),
		Components:   components,
		Dependencies: dependencies,
		Roots:        roots,
	}, nil
}

func sanitizeSPDXID(raw string) string {
	if raw == "" {
		return "pkg"
	}
	var b strings.Builder
	b.Grow(len(raw))
	lastDash := false
	for _, r := range raw {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "pkg"
	}
	return out
}

func extractSPDXToolName(ci *v23.CreationInfo) string {
	tools := extractSPDXToolNames(ci)
	if len(tools) > 0 {
		return tools[0]
	}
	return ""
}

func extractSPDXToolNames(ci *v23.CreationInfo) []string {
	if ci == nil {
		return nil
	}
	tools := make([]string, 0, len(ci.Creators))
	for _, c := range ci.Creators {
		if c.CreatorType == "Tool" {
			tools = append(tools, c.Creator)
		}
	}
	return tools
}

func parseSPDXCreated(ci *v23.CreationInfo) time.Time {
	if ci == nil || ci.Created == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, ci.Created)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func spdxPackageComment(component Component) string {
	fields := make([]string, 0, 4)
	if scope := strings.TrimSpace(component.Scope); scope != "" {
		fields = append(fields, "scope="+scope)
	}
	if typ := strings.TrimSpace(component.Type); typ != "" && !strings.EqualFold(typ, "package") {
		fields = append(fields, "type="+typ)
	}
	if component.EOL != nil {
		fields = append(fields, "eol="+strconv.FormatBool(component.EOL.EOL))
		if date := strings.TrimSpace(component.EOL.EOLDate); date != "" {
			fields = append(fields, "eol_date="+date)
		}
	}
	if len(fields) == 0 {
		return ""
	}
	return "bomly:" + strings.Join(fields, ";")
}

// spdxChecksums maps component digests onto SPDX package checksums, dropping
// entries whose algorithm is not part of the SPDX checksum vocabulary.
func spdxChecksums(digests []Digest) []common.Checksum {
	if len(digests) == 0 {
		return nil
	}
	out := make([]common.Checksum, 0, len(digests))
	for _, d := range digests {
		alg := spdxChecksumAlgorithm(d.Algorithm)
		if alg == "" || strings.TrimSpace(d.Value) == "" {
			continue
		}
		out = append(out, common.Checksum{Algorithm: alg, Value: d.Value})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// spdxChecksumAlgorithm maps a digest algorithm spelling onto the SPDX 2.3
// checksum algorithm constant that names it, delegating to the SDK's digest
// registry rather than transcribing the enumeration here. The registry is
// built from spdx/tools-golang's own constants and accepts every spelling
// either SBOM format uses, so "SHA-256", "sha256" and "SHA256" all resolve.
//
// Returns "" when the algorithm is unknown or SPDX has no member for it, so
// the digest is dropped rather than emitting a BOM that fails validation.
func spdxChecksumAlgorithm(algorithm string) common.ChecksumAlgorithm {
	parsed, err := sdk.ParseDigestAlgorithm(algorithm)
	if err != nil {
		return ""
	}
	return common.ChecksumAlgorithm(parsed.SPDXName())
}

func parseSPDXComponentType(p *v23.Package) string {
	if p == nil {
		return ""
	}
	if value := parseSPDXCommentField(p.PackageComment, "type"); value != "" {
		return value
	}
	return strings.ToLower(strings.TrimSpace(p.PrimaryPackagePurpose))
}

func parseSPDXCommentField(comment, field string) string {
	comment = strings.TrimSpace(comment)
	if !strings.HasPrefix(comment, "bomly:") {
		return ""
	}
	for part := range strings.SplitSeq(strings.TrimPrefix(comment, "bomly:"), ";") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), field) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// spdxLicenseValue renders a component's licenses into one SPDX license field,
// with the extracted-text entries the field's references depend on.
//
// SPDX 2.3 has no free-text license field. licenseDeclared must hold a valid
// expression, NOASSERTION, NONE, or a LicenseRef-* identifier, so a registry
// value like "see LICENSE file" cannot be written verbatim -- which is what
// this did, producing a document a strict consumer can reject, and the lite
// build hands that document to an external tool. Each unrecognized value
// mints a reference instead, and the original text travels beside it in
// hasExtractedLicensingInfos. That is what SPDX defines for this case, and
// unlike NOASSERTION it keeps the information: an ingest can read the text
// back.
//
// Minting is the kit's, not this package's. A reference has to be
// deterministic, collision-free across components without coordination, and
// restricted to the characters the idstring grammar allows; spdxkit.MintLicenseRef
// answers all three by hashing, and hand-rolling a sanitizer here would be a
// second, worse answer to a question the SDK already settled.
//
// SPDX 2.3 holds a single expression per package and has no way to list
// licenses without relating them, so a component carrying several composes
// them. AND is the conservative reading -- it overstates obligations rather
// than understating them -- but it is still more than a source that merely
// listed licenses actually said. CycloneDX lists them instead; this is the
// one place the two formats differ.
//
// A source that knows the relationship states it in one value ("Apache-2.0 OR
// MIT"), which arrives here as a single value and passes through untouched.
func spdxLicenseValue(licenses []License) (string, []spdxkit.ExtractedText) {
	values := componentLicenseValues(licenses)
	if len(values) == 0 {
		return "NOASSERTION", nil
	}

	elements := make([]string, 0, len(values))
	var extracted []spdxkit.ExtractedText
	for _, value := range values {
		if spdxkit.Classify(value) == spdxkit.ClassFreeText {
			ref := spdxkit.MintLicenseRef(value)
			elements = append(elements, ref.RefID)
			extracted = append(extracted, ref)
			continue
		}
		elements = append(elements, value)
	}
	if len(elements) == 1 {
		return elements[0], extracted
	}
	return spdxkit.Compose(elements), extracted
}

// spdxOtherLicenses renders the document's extracted-text section: one entry
// per distinct reference, sorted by identifier so the document is stable.
//
// The entries are document-scoped while the references that need them are
// written per package, so they are collected during package assembly and
// emitted once here. Two components carrying the same unrecognized text mint
// the same reference and collapse to one entry, which is the property that
// makes the reference safe to share.
func spdxOtherLicenses(extracted []spdxkit.ExtractedText) []*v23.OtherLicense {
	if len(extracted) == 0 {
		return nil
	}
	byRef := make(map[string]spdxkit.ExtractedText, len(extracted))
	for _, entry := range extracted {
		if entry.RefID == "" {
			continue
		}
		byRef[entry.RefID] = entry
	}
	refs := make([]string, 0, len(byRef))
	for ref := range byRef {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	out := make([]*v23.OtherLicense, 0, len(refs))
	for _, ref := range refs {
		out = append(out, &v23.OtherLicense{
			LicenseIdentifier: ref,
			ExtractedText:     byRef[ref].Text,
		})
	}
	return out
}

// spdxCommentEOL reads the end-of-life claim back out of the package comment.
//
// SPDX writes only the flag and the date -- it has no cycle field in this
// comment -- so only those are read. The flag is what makes the record exist:
// a date alone says nothing about whether the version is end-of-life, and an
// unparseable flag drops the record rather than guessing at one. Without this
// the fields were write-only, and a conversion dropped a claim the document
// plainly stated.
func spdxCommentEOL(comment string) *EOL {
	value := strings.TrimSpace(parseSPDXCommentField(comment, "eol"))
	if value == "" {
		return nil
	}
	flag, err := strconv.ParseBool(value)
	if err != nil {
		return nil
	}
	return &EOL{EOL: flag, EOLDate: strings.TrimSpace(parseSPDXCommentField(comment, "eol_date"))}
}

func spdxCopyrightValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return value
}

func spdxExternalReferences(component Component) []*v23.PackageExternalReference {
	refs := make([]*v23.PackageExternalReference, 0, 1+len(component.CPEs)+len(component.Vulnerabilities))
	if purl := strings.TrimSpace(component.PURL); purl != "" {
		refs = append(refs, &v23.PackageExternalReference{
			Category: "PACKAGE-MANAGER",
			RefType:  "purl",
			Locator:  purl,
		})
	}
	for _, cpe := range component.CPEs {
		cpe = strings.TrimSpace(cpe)
		if cpe == "" {
			continue
		}
		refs = append(refs, &v23.PackageExternalReference{
			Category: "SECURITY",
			RefType:  "cpe23Type",
			Locator:  cpe,
		})
	}
	for _, vuln := range component.Vulnerabilities {
		locator := spdxVulnerabilityLocator(vuln)
		if locator == "" {
			continue
		}
		refs = append(refs, &v23.PackageExternalReference{
			Category: "SECURITY",
			RefType:  "advisory",
			Locator:  locator,
		})
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// spdxVulnerabilityLocator returns the best URL for a vulnerability external
// reference, falling back to the advisory ID when no reference URL is known.
func spdxVulnerabilityLocator(vuln Vulnerability) string {
	if len(vuln.Advisories) > 0 {
		if url := strings.TrimSpace(vuln.Advisories[0]); url != "" {
			return url
		}
	}
	return strings.TrimSpace(vuln.ID)
}

// spdxExtractedTexts indexes a document's extracted-license section by
// reference, so ingest can read back the text an exported reference names.
//
// An entry whose text does not mint its own identifier is kept under the
// identifier the document wrote, not repaired. This is a foreign document:
// the pairing it states is what it means, and re-minting would answer with a
// reference the document never used.
func spdxExtractedTexts(others []*v23.OtherLicense) map[string]string {
	if len(others) == 0 {
		return nil
	}
	byRef := make(map[string]string, len(others))
	for _, other := range others {
		if other == nil {
			continue
		}
		ref := strings.TrimSpace(other.LicenseIdentifier)
		if ref == "" {
			continue
		}
		byRef[ref] = other.ExtractedText
	}
	return byRef
}

// parseSPDXLicenses reads a package's license fields back into the model,
// resolving any reference to the text the document extracted for it.
//
// Export mints a reference for a value SPDX cannot hold verbatim, so ingest
// has to undo it or a round trip would return "LicenseRef-<hash>" where the
// source said "see LICENSE file" -- information the reference exists to
// preserve, lost at the boundary that was supposed to carry it.
//
// The expression keeps the reference and the value carries the text: the
// first is what the document said, the second is what a human means, and
// collapsing them would make the resolved text look like a license
// identifier to everything downstream.
func parseSPDXLicenses(extractedByRef map[string]string, values ...string) []License {
	for _, value := range values {
		value = strings.TrimSpace(value)
		switch value {
		case "", "NOASSERTION", "NONE":
			continue
		default:
			license := License{SPDXExpression: value, Value: value}
			if text, ok := resolveSingleLicenseRef(extractedByRef, value); ok {
				license.Value = text
			}
			return []License{license}
		}
	}
	return nil
}

// resolveSingleLicenseRef returns the extracted text when the expression is
// exactly one reference and the document supplied its text.
//
// Only the atomic case resolves. A compound expression naming a reference
// among other terms ("MIT AND LicenseRef-abc") has no single text to become:
// substituting free text into it would produce something that no longer
// parses, and the reference is already the correct representation there.
func resolveSingleLicenseRef(extractedByRef map[string]string, expression string) (string, bool) {
	if len(extractedByRef) == 0 {
		return "", false
	}
	refs := spdxkit.LicenseRefsIn(expression)
	if len(refs) != 1 || refs[0] != expression {
		return "", false
	}
	text, ok := extractedByRef[expression]
	if !ok || strings.TrimSpace(text) == "" {
		return "", false
	}
	return text, true
}

func parseSPDXPURL(refs []*v23.PackageExternalReference) string {
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(ref.Category), "PACKAGE-MANAGER") &&
			strings.EqualFold(strings.TrimSpace(ref.RefType), "purl") {
			return strings.TrimSpace(ref.Locator)
		}
	}
	return ""
}

func parseSPDXPackageManager(refs []*v23.PackageExternalReference) string {
	purl := parseSPDXPURL(refs)
	if manager := packageManagerForPURL(purl, "", ""); manager != sdk.PackageManagerUnknown {
		return manager.Name()
	}
	return ""
}

func parseSPDXEcosystem(refs []*v23.PackageExternalReference) string {
	purl := parseSPDXPURL(refs)
	if parsed := parsePURL(purl); parsed != nil {
		return string(sdk.EcosystemForPURLType(parsed.Type))
	}
	return ""
}

func parseSPDXCopyright(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "", "NOASSERTION", "NONE":
		return ""
	default:
		return value
	}
}
