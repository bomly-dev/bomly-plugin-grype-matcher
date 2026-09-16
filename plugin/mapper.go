package plugin

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-sdk/model"
)

type grypeAdvisory struct {
	ID                   string
	Namespace            string
	DataSource           string
	Severity             string
	SeveritySource       string
	Description          string
	URLs                 []string
	CVSS                 []model.CVSSScore
	FixedVersions        []string
	FixedIn              string
	FixState             model.FixState
	FixAvailable         []model.FixAvailable
	AffectedVersionRange string
	References           []model.Reference
	Aliases              []string
	KnownExploited       []model.KnownExploited
	EPSS                 []model.EPSSScore
	CWEs                 []model.CWE
	RiskScore            float64
	CPEs                 []string
}

func mapGrypeAdvisory(advisory grypeAdvisory) model.Vulnerability {
	fixedIn := strings.TrimSpace(advisory.FixedIn)
	if fixedIn == "" && len(advisory.FixedVersions) > 0 {
		fixedIn = strings.TrimSpace(advisory.FixedVersions[0])
	}
	severity := model.ParseSeverityLevel(advisory.Severity)
	description := strings.TrimSpace(advisory.Description)
	title := strings.TrimSpace(advisory.ID)
	if description != "" {
		title = description
	}
	refs := append([]model.Reference(nil), advisory.References...)
	if advisory.DataSource != "" {
		refs = appendUniqueReference(refs, model.Reference{URL: advisory.DataSource, Type: model.ReferenceTypeDataSource})
	}
	for _, url := range advisory.URLs {
		refs = appendUniqueReference(refs, model.Reference{URL: url, Type: model.ReferenceTypeAdvisory})
	}

	return model.Vulnerability{
		ID:                   advisory.ID,
		Title:                title,
		ParsedSeverity:       severity,
		SeveritySource:       advisory.SeveritySource,
		Aliases:              dedupeStrings(advisory.Aliases),
		Details:              description,
		Reasons:              grypeReasons(advisory, fixedIn),
		Source:               matcherName,
		CVSS:                 append([]model.CVSSScore(nil), advisory.CVSS...),
		FixedIn:              fixedIn,
		FixedVersions:        dedupeStrings(advisory.FixedVersions),
		FixState:             advisory.FixState,
		FixAvailable:         append([]model.FixAvailable(nil), advisory.FixAvailable...),
		AffectedVersionRange: advisory.AffectedVersionRange,
		References:           refs,
		KEVExploited:         len(advisory.KnownExploited) > 0,
		KnownExploited:       cloneKnownExploited(advisory.KnownExploited),
		EPSS:                 append([]model.EPSSScore(nil), advisory.EPSS...),
		CWEs:                 append([]model.CWE(nil), advisory.CWEs...),
		RiskScore:            advisory.RiskScore,
		DataSource:           advisory.DataSource,
		Namespace:            advisory.Namespace,
		CPEs:                 dedupeStrings(advisory.CPEs),
	}
}

func grypeReasons(advisory grypeAdvisory, fixedIn string) []string {
	reasons := make([]string, 0, 4)
	if fixedIn != "" {
		reasons = append(reasons, fmt.Sprintf("Fix available: upgrade to %s", fixedIn))
	}
	if advisory.FixState != "" {
		reasons = append(reasons, "Fix state: "+string(advisory.FixState))
	}
	if len(advisory.Aliases) > 0 {
		reasons = append(reasons, "Also known as: "+strings.Join(dedupeStrings(advisory.Aliases), ", "))
	}
	if len(advisory.URLs) > 0 {
		reasons = append(reasons, advisory.URLs...)
	}
	return reasons
}

func mergePackageVulnerability(base, incoming model.Vulnerability) model.Vulnerability {
	base.Title = firstNonEmpty(base.Title, incoming.Title)
	base.ParsedSeverity = model.ParseSeverityLevel(firstNonEmpty(string(base.ParsedSeverity), string(incoming.ParsedSeverity)))
	base.SeveritySource = firstNonEmpty(base.SeveritySource, incoming.SeveritySource)
	base.Details = firstNonEmpty(base.Details, incoming.Details)
	base.FixedIn = firstNonEmpty(base.FixedIn, incoming.FixedIn)
	base.FixState = model.FixState(firstNonEmpty(string(base.FixState), string(incoming.FixState)))
	base.AffectedVersionRange = firstNonEmpty(base.AffectedVersionRange, incoming.AffectedVersionRange)
	base.DataSource = firstNonEmpty(base.DataSource, incoming.DataSource)
	base.Namespace = firstNonEmpty(base.Namespace, incoming.Namespace)
	if base.RiskScore == 0 {
		base.RiskScore = incoming.RiskScore
	}
	base.KEVExploited = base.KEVExploited || incoming.KEVExploited
	base.Aliases = appendUniqueStrings(base.Aliases, incoming.Aliases...)
	base.Reasons = appendUniqueStrings(base.Reasons, incoming.Reasons...)
	base.CVSS = appendUniqueCVSS(base.CVSS, incoming.CVSS...)
	base.FixedVersions = appendUniqueStrings(base.FixedVersions, incoming.FixedVersions...)
	base.FixAvailable = appendUniqueFixAvailable(base.FixAvailable, incoming.FixAvailable...)
	base.References = appendUniqueReferences(base.References, incoming.References...)
	base.KnownExploited = appendUniqueKnownExploited(base.KnownExploited, incoming.KnownExploited...)
	base.EPSS = appendUniqueEPSS(base.EPSS, incoming.EPSS...)
	base.CWEs = appendUniqueCWEs(base.CWEs, incoming.CWEs...)
	base.CPEs = appendUniqueStrings(base.CPEs, incoming.CPEs...)
	return base
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func dedupeStrings(values []string) []string {
	return appendUniqueStrings(nil, values...)
}

func appendUniqueStrings(existing []string, values ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]string, 0, len(existing)+len(values))
	for _, value := range existing {
		key := strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	for _, value := range values {
		key := strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func appendUniqueReference(existing []model.Reference, ref model.Reference) []model.Reference {
	return appendUniqueReferences(existing, ref)
}

func appendUniqueReferences(existing []model.Reference, values ...model.Reference) []model.Reference {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]model.Reference, 0, len(existing)+len(values))
	for _, ref := range existing {
		key := ref.URL + "\x00" + string(ref.Type)
		if strings.TrimSpace(ref.URL) == "" || key == "\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ref)
	}
	for _, ref := range values {
		key := ref.URL + "\x00" + string(ref.Type)
		if strings.TrimSpace(ref.URL) == "" || key == "\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func appendUniqueCVSS(existing []model.CVSSScore, values ...model.CVSSScore) []model.CVSSScore {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]model.CVSSScore, 0, len(existing)+len(values))
	for _, score := range append(existing, values...) {
		key := score.Source + "\x00" + string(score.Version) + "\x00" + score.Vector
		if key == "\x00\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, score)
	}
	return out
}

func appendUniqueFixAvailable(existing []model.FixAvailable, values ...model.FixAvailable) []model.FixAvailable {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]model.FixAvailable, 0, len(existing)+len(values))
	for _, fix := range append(existing, values...) {
		key := fix.Version + "\x00" + fix.Date + "\x00" + string(fix.Kind)
		if key == "\x00\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, fix)
	}
	return out
}

func appendUniqueEPSS(existing []model.EPSSScore, values ...model.EPSSScore) []model.EPSSScore {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]model.EPSSScore, 0, len(existing)+len(values))
	for _, epss := range append(existing, values...) {
		key := epss.CVE + "\x00" + epss.Date
		if key == "\x00" && epss.EPSS == 0 && epss.Percentile == 0 {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, epss)
	}
	return out
}

func appendUniqueCWEs(existing []model.CWE, values ...model.CWE) []model.CWE {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]model.CWE, 0, len(existing)+len(values))
	for _, cwe := range append(existing, values...) {
		key := cwe.CVE + "\x00" + cwe.ID + "\x00" + cwe.Source + "\x00" + cwe.Type
		if key == "\x00\x00\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cwe)
	}
	return out
}

func cloneKnownExploited(src []model.KnownExploited) []model.KnownExploited {
	return appendUniqueKnownExploited(nil, src...)
}

func appendUniqueKnownExploited(existing []model.KnownExploited, values ...model.KnownExploited) []model.KnownExploited {
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]model.KnownExploited, 0, len(existing)+len(values))
	for _, item := range append(existing, values...) {
		key := item.CVE + "\x00" + item.DateAdded + "\x00" + item.Product
		if key == "\x00\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if len(item.URLs) > 0 {
			item.URLs = append([]string(nil), item.URLs...)
		}
		if len(item.CWEs) > 0 {
			item.CWEs = append([]string(nil), item.CWEs...)
		}
		out = append(out, item)
	}
	return out
}
