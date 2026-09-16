//go:build bomly_external_grype

package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	logkit "github.com/bomly-dev/bomly-sdk/logkit"
	matchers "github.com/bomly-dev/bomly-sdk/matcherkit"
	"github.com/bomly-dev/bomly-sdk/sbom"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// Ready reports whether the external grype binary is available.
func (a Matcher) Ready(context.Context, sdkplugin.MatchRequest) error {
	if _, err := exec.LookPath("grype"); err != nil {
		return fmt.Errorf("grype executable not found on PATH: %w", err)
	}
	return nil
}

// Match attaches Grype vulnerability matches by shelling out to the grype CLI binary.
func (a Matcher) Match(_ context.Context, req sdkplugin.MatchRequest) (sdkplugin.MatchResult, error) {
	started := time.Now()
	if req.Graph == nil {
		return sdkplugin.MatchResult{MatcherStats: grypeMatcherStats(0, 0, 0)}, nil
	}

	logger := a.logger()

	if req.Graph == nil || req.Registry == nil {
		return sdkplugin.MatchResult{Registry: req.Registry, MatcherStats: grypeMatcherStats(0, 0, 0)}, nil
	}

	// Seed the registry so SPDX serialization and match correlation share PURLs.
	_ = matchers.RegistryPackagesForGraph(req.Graph, req.Registry, req.Target)

	// Serialize graph as SPDX JSON to feed to grype stdin.
	spdxBytes, err := sbom.MarshalDepGraphJSON(req.Graph, sbom.TargetSPDX23JSON, sbom.BuildOptions{}, sbom.EncodeOptions{})
	if err != nil {
		return sdkplugin.MatchResult{Registry: req.Registry, MatcherStats: grypeMatcherStats(0, 0, 0)}, fmt.Errorf("grype: serialize sbom: %w", err)
	}

	args := []string{"-o", "json"}
	var stdout bytes.Buffer
	commandStderr := logkit.NewCommandStderr(req.Stderr, req.Stderr != nil)
	cmd := system.Command("grype", args...)
	cmd.Stdin = bytes.NewReader(spdxBytes)
	cmd.Stdout = &stdout
	cmd.Stderr = commandStderr

	logger.Debug("running external grype matcher", logkit.CommandFields("grype", args, cmd.Dir)...)
	if err := cmd.Run(); err != nil {
		logger.Warn("grype CLI failed", zap.Error(err), zap.Int64("stderr_bytes", commandStderr.ByteCount()))
		return sdkplugin.MatchResult{Registry: req.Registry, MatcherStats: grypeMatcherStats(0, 0, 0)}, fmt.Errorf("grype match failed: %w", err)
	}

	matchedPackages, vulnerabilities, err := parseGrypeJSONOutput(stdout.Bytes(), req.Registry, firstPartyPURLs(req.Graph))
	if err != nil {
		return sdkplugin.MatchResult{Registry: req.Registry, MatcherStats: grypeMatcherStats(0, 0, 0)}, fmt.Errorf("grype: parse output: %w", err)
	}

	logger.Info(fmt.Sprintf("External grype enrichment completed in %s", formatDuration(time.Since(started))))
	return sdkplugin.MatchResult{
		Registry:     req.Registry,
		MatcherStats: grypeMatcherStats(matchedPackages, registryPackageCount(req.Registry)-matchedPackages, vulnerabilities),
	}, nil
}

// grypeJSONOutput represents the top-level structure of grype JSON output.
type grypeJSONOutput struct {
	Matches []grypeJSONMatch `json:"matches"`
}

type grypeJSONMatch struct {
	Vulnerability          grypeJSONVuln       `json:"vulnerability"`
	RelatedVulnerabilities []grypeJSONVulnMeta `json:"relatedVulnerabilities"`
	MatchDetails           []grypeJSONDetail   `json:"matchDetails"`
	Artifact               grypeJSONArtifact   `json:"artifact"`
}

type grypeJSONVuln struct {
	grypeJSONVulnMeta
	Fix        grypeJSONFix        `json:"fix"`
	Advisories []grypeJSONAdvisory `json:"advisories"`
	Risk       float64             `json:"risk"`
}

type grypeJSONVulnMeta struct {
	ID             string                  `json:"id"`
	DataSource     string                  `json:"dataSource"`
	Namespace      string                  `json:"namespace"`
	Severity       string                  `json:"severity"`
	URLs           []string                `json:"urls"`
	Description    string                  `json:"description"`
	CVSS           []grypeJSONCVSS         `json:"cvss"`
	KnownExploited []grypeJSONKnownExploit `json:"knownExploited"`
	EPSS           []grypeJSONEPSS         `json:"epss"`
	CWEs           []grypeJSONCWE          `json:"cwes"`
}

type grypeJSONFix struct {
	Versions  []string                `json:"versions"`
	State     string                  `json:"state"`
	Available []grypeJSONFixAvailable `json:"available"`
}

type grypeJSONFixAvailable struct {
	Version string `json:"version"`
	Date    string `json:"date"`
	Kind    string `json:"kind"`
}

type grypeJSONAdvisory struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}

type grypeJSONCVSS struct {
	Source  string              `json:"source"`
	Type    string              `json:"type"`
	Version string              `json:"version"`
	Vector  string              `json:"vector"`
	Metrics grypeJSONCVSSMetric `json:"metrics"`
}

type grypeJSONCVSSMetric struct {
	BaseScore float64 `json:"baseScore"`
}

type grypeJSONKnownExploit struct {
	CVE                        string   `json:"cve"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	DateAdded                  string   `json:"dateAdded"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	URLs                       []string `json:"urls"`
	CWEs                       []string `json:"cwes"`
}

type grypeJSONEPSS struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

type grypeJSONCWE struct {
	CVE    string `json:"cve"`
	CWE    string `json:"cwe"`
	Source string `json:"source"`
	Type   string `json:"type"`
}

type grypeJSONDetail struct {
	Found json.RawMessage      `json:"found"`
	Fix   *grypeJSONFixDetails `json:"fix"`
}

type grypeJSONFixDetails struct {
	SuggestedVersion string `json:"suggestedVersion"`
}

type grypeJSONArtifact struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	CPEs    []string `json:"cpes"`
	PURL    string   `json:"purl"`
}

// firstPartyPURLs collects the PURLs of graph nodes that must not receive
// external matches (sdk.NodeIsEnrichable is false). The SBOM handed to grype
// intentionally keeps first-party components — the transform is shared with
// user-facing SBOM output — so their matches are dropped on the way back in.
func firstPartyPURLs(g *model.Graph) map[string]struct{} {
	if g == nil {
		return nil
	}
	skip := make(map[string]struct{})
	// Module nodes first. The project's own artifacts -- workspace members,
	// reactor modules -- used to be dependency nodes carrying FirstParty, and
	// this walked DependencyNodes() to find them. ADR-0041 made ownership the
	// node kind, so they are module nodes and DependencyNodes() never yields
	// one: walking only dependencies would have silently stopped skipping
	// them, and grype findings against the project's own packages would have
	// been admitted to the registry.
	for _, module := range g.ModuleNodes() {
		if module == nil {
			continue
		}
		for _, purl := range []string{strings.TrimSpace(module.Coordinates.PURL), module.NodeID()} {
			if purl != "" {
				skip[purl] = struct{}{}
			}
		}
	}
	// A dependency node can still be ineligible for registry matching on its
	// own terms -- a git-sourced package, for instance -- and those are
	// skipped too.
	for _, dep := range g.DependencyNodes() {
		if dep == nil || dep.RegistryMatchEligible() {
			continue
		}
		// Coordinates.PURL explicitly: PURL is a method on the node now and
		// shadows the embedded field. Both spellings are still wanted -- the
		// coordinate PURL is what the source said, the node ID is the
		// canonical form -- so grype output matching either is skipped.
		for _, purl := range []string{strings.TrimSpace(dep.Coordinates.PURL), dep.NodeID()} {
			if purl != "" {
				skip[purl] = struct{}{}
			}
		}
	}
	return skip
}

func parseGrypeJSONOutput(data []byte, registry *model.PackageRegistry, skipPURLs map[string]struct{}) (int, int, error) {
	var out grypeJSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, 0, fmt.Errorf("decode grype json: %w", err)
	}
	if registry == nil {
		return 0, len(out.Matches), nil
	}

	seen := make(map[string]struct{})
	vulnerabilities := 0
	for _, m := range out.Matches {
		purl := strings.TrimSpace(m.Artifact.PURL)
		if purl == "" {
			continue
		}
		if _, firstParty := skipPURLs[purl]; firstParty {
			continue
		}
		seen[purl] = struct{}{}
		vulnerabilities++
		pkg := registry.Ensure(purl)
		if pkg == nil {
			continue
		}
		pkg.Matched = true
		pkg.Vulnerabilities = appendOrMergeVulnerability(pkg.Vulnerabilities, mapGrypeJSONMatch(m))
	}
	return len(seen), vulnerabilities, nil
}

func registryPackageCount(registry *model.PackageRegistry) int {
	if registry == nil {
		return 0
	}
	return len(registry.All())
}

func mapGrypeJSONMatch(m grypeJSONMatch) model.Vulnerability {
	advisory := grypeAdvisory{
		ID:                   m.Vulnerability.ID,
		Namespace:            m.Vulnerability.Namespace,
		DataSource:           m.Vulnerability.DataSource,
		Severity:             m.Vulnerability.Severity,
		SeveritySource:       m.Vulnerability.Namespace,
		Description:          m.Vulnerability.Description,
		URLs:                 append([]string(nil), m.Vulnerability.URLs...),
		CVSS:                 jsonCVSS(m.Vulnerability.CVSS),
		FixedVersions:        append([]string(nil), m.Vulnerability.Fix.Versions...),
		FixedIn:              suggestedFixedVersion(m.MatchDetails),
		FixState:             model.FixState(m.Vulnerability.Fix.State),
		FixAvailable:         jsonFixAvailable(m.Vulnerability.Fix.Available),
		AffectedVersionRange: foundConstraint(m.MatchDetails),
		References:           jsonReferences(m.Vulnerability.Advisories),
		Aliases:              jsonAliases(m.RelatedVulnerabilities),
		KnownExploited:       jsonKnownExploited(m.Vulnerability.KnownExploited),
		EPSS:                 jsonEPSS(m.Vulnerability.EPSS),
		CWEs:                 jsonCWEs(m.Vulnerability.CWEs),
		RiskScore:            m.Vulnerability.Risk,
		CPEs:                 append([]string(nil), m.Artifact.CPEs...),
	}
	return mapGrypeAdvisory(advisory)
}

func suggestedFixedVersion(details []grypeJSONDetail) string {
	for _, detail := range details {
		if detail.Fix != nil && detail.Fix.SuggestedVersion != "" {
			return detail.Fix.SuggestedVersion
		}
	}
	return ""
}

func foundConstraint(details []grypeJSONDetail) string {
	for _, detail := range details {
		var found struct {
			Constraint string `json:"constraint"`
		}
		if len(detail.Found) == 0 || json.Unmarshal(detail.Found, &found) != nil {
			continue
		}
		if found.Constraint != "" {
			return found.Constraint
		}
	}
	return ""
}

func jsonCVSS(values []grypeJSONCVSS) []model.CVSSScore {
	out := make([]model.CVSSScore, 0, len(values))
	for _, value := range values {
		out = append(out, model.CVSSScore{
			Vector:  value.Vector,
			Score:   value.Metrics.BaseScore,
			Version: model.SeverityType(value.Version),
			Source:  value.Source,
		})
	}
	return out
}

func jsonFixAvailable(values []grypeJSONFixAvailable) []model.FixAvailable {
	out := make([]model.FixAvailable, 0, len(values))
	for _, value := range values {
		out = append(out, model.FixAvailable{Version: value.Version, Date: value.Date, Kind: model.FixAvailableKind(value.Kind)})
	}
	return out
}

func jsonReferences(values []grypeJSONAdvisory) []model.Reference {
	out := make([]model.Reference, 0, len(values))
	for _, value := range values {
		out = append(out, model.Reference{URL: value.Link, Type: model.ReferenceType(firstNonEmpty(value.ID, string(model.ReferenceTypeAdvisory)))})
	}
	return out
}

func jsonAliases(values []grypeJSONVulnMeta) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.ID)
	}
	return out
}

func jsonKnownExploited(values []grypeJSONKnownExploit) []model.KnownExploited {
	out := make([]model.KnownExploited, 0, len(values))
	for _, value := range values {
		out = append(out, model.KnownExploited{
			CVE:                        value.CVE,
			VendorProject:              value.VendorProject,
			Product:                    value.Product,
			DateAdded:                  value.DateAdded,
			RequiredAction:             value.RequiredAction,
			DueDate:                    value.DueDate,
			KnownRansomwareCampaignUse: value.KnownRansomwareCampaignUse,
			Notes:                      value.Notes,
			URLs:                       append([]string(nil), value.URLs...),
			CWEs:                       append([]string(nil), value.CWEs...),
		})
	}
	return out
}

func jsonEPSS(values []grypeJSONEPSS) []model.EPSSScore {
	out := make([]model.EPSSScore, 0, len(values))
	for _, value := range values {
		out = append(out, model.EPSSScore{CVE: value.CVE, EPSS: value.EPSS, Percentile: value.Percentile, Date: value.Date})
	}
	return out
}

func jsonCWEs(values []grypeJSONCWE) []model.CWE {
	out := make([]model.CWE, 0, len(values))
	for _, value := range values {
		out = append(out, model.CWE{CVE: value.CVE, ID: value.CWE, Source: value.Source, Type: value.Type})
	}
	return out
}

// supportedEcosystems is nil in external mode: the graph is handed to the grype
// CLI as an SPDX document, so coverage is whatever that binary derives from the
// PURLs rather than anything this package maps. nil reads as "all ecosystems",
// which is the honest answer here.
var supportedEcosystems []model.Ecosystem
