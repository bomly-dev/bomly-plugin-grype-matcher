//go:build !bomly_external_grype

package plugin

import (
	"context"
	"fmt"
	"strings"
	"time"

	grypeclio "github.com/anchore/clio"
	grypelib "github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	grypematch "github.com/anchore/grype/grype/match"
	grypematcher "github.com/anchore/grype/grype/matcher"
	grypepkg "github.com/anchore/grype/grype/pkg"
	grypevuln "github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
	matchers "github.com/bomly-dev/bomly-sdk/matcherkit"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// clioID is the clio application identity presented when opening the Grype vulnerability DB.
var clioID = grypeclio.Identification{Name: "grype"}

// defaultDBMaxAge is the age past which the database is reported stale. It
// is Grype's own MaxAllowedBuiltAge default; Grype refuses to load a database
// older than that, this matcher warns and matches anyway.
const defaultDBMaxAge = 5 * 24 * time.Hour

// Ready reports whether the bundled Grype matcher can run. The database may be
// downloaded during Match on first use, so a missing cache does not make the
// matcher unavailable.
func (a Matcher) Ready(context.Context, sdkplugin.MatchRequest) error {
	return nil
}

// Match attaches Grype vulnerability matches to packages in the graph.
func (a Matcher) Match(_ context.Context, req sdkplugin.MatchRequest) (sdkplugin.MatchResult, error) {
	started := time.Now()
	if req.Graph == nil || req.Registry == nil {
		return sdkplugin.MatchResult{Registry: req.Registry, MatcherStats: grypeMatcherStats(0, 0, 0)}, nil
	}

	logger := a.logger()

	distCfg := v6dist.DefaultConfig()
	if dc, ok := a.DistConfigOverride.(*v6dist.Config); ok && dc != nil {
		distCfg = *dc
	}
	distCfg.ID = clioID

	logger.Debug(fmt.Sprintf("Grype loading vulnerability database from %s", a.dbDir()))
	provider, status, err := openVulnerabilityDB(a, logger, distCfg)
	if err != nil {
		logger.Warn("Grype failed to load vulnerability DB, skipping", zap.Error(err))
		return sdkplugin.MatchResult{Registry: req.Registry, MatcherStats: grypeMatcherStats(0, 0, 0)}, fmt.Errorf("grype vulnerability DB unavailable: %w", err)
	}
	// The provider holds an open SQLite reader, and the caller owns it, as
	// grype's own CLI does when it defers closing it. Each Match opens its own,
	// so closing it here is safe while another call is still matching; left
	// open, a managed plugin serving many calls leaked one handle per call
	// (bomly-plugin-grype-matcher#19).
	defer func() {
		if err := provider.Close(); err != nil {
			logger.Debug("Grype vulnerability DB reader did not close cleanly", zap.Error(err))
		}
	}()
	a.reportDBAge(logger, status.Built, time.Now())

	packages := matchers.RegistryPackagesForGraph(req.Graph, req.Registry, req.Target)
	logger.Info(fmt.Sprintf("Grype enriching %d packages with vulnerability data", len(packages)))
	grypePkgs := make([]grypepkg.Package, 0, len(packages))
	for _, p := range packages {
		if p.Name == "" {
			continue
		}
		grypePkgs = append(grypePkgs, graphPkgToGrypePkg(p))
	}

	matcher := grypematcher.NewDefaultMatchers(grypematcher.Config{})
	vm := &grypelib.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              matcher,
	}

	matches, _, err := vm.FindMatches(grypePkgs, grypepkg.Context{})
	if err != nil {
		return sdkplugin.MatchResult{Registry: req.Registry, MatcherStats: grypeMatcherStats(0, len(packages), 0)}, fmt.Errorf("grype: find matches: %w", err)
	}

	applyMatches(matches, req.Registry)
	matchedPackages, vulnerabilities := grypeMatchCounts(matches)
	logger.Info(fmt.Sprintf("Grype enrichment matched vulnerabilities in %s", formatDuration(time.Since(started))))
	return sdkplugin.MatchResult{
		Registry:     req.Registry,
		MatcherStats: grypeMatcherStats(matchedPackages, len(packages)-matchedPackages, vulnerabilities),
	}, nil
}

// openVulnerabilityDB is how Match opens the database: Matcher.loadDB, held
// in a variable so a test can substitute a provider and observe that Match
// releases it.
var openVulnerabilityDB = Matcher.loadDB

// loadDB opens the local Grype database, first asking Grype's curator to
// refresh it unless DisableDBUpdate is set. This is what grype.LoadVulnerabilityDB
// does, inlined so the update outcome reaches Bomly's logger: the library
// reports it only through Grype's own logger, which is not wired up here.
//
// The curator does the actual work. With no database it downloads one. With
// one present it asks the distribution service for a newer build at most once
// per UpdateCheckMaxFrequency and installs it when there is one. Until v0.6.0
// this matcher asked only when the directory was missing, so a database
// downloaded once was used for ever, and an enriched scan reported nothing
// published after it was built -- silently (bomly-dev/bomly-cli#510).
func (a Matcher) loadDB(logger *zap.Logger, distCfg v6dist.Config) (grypevuln.Provider, *grypevuln.ProviderStatus, error) {
	installCfg := v6inst.DefaultConfig(clioID)
	installCfg.DBRootDir = a.dbDir()
	// An old database still matches, so its age is reported by reportDBAge
	// rather than enforced: with ValidateAge on, the curator refuses to open
	// a database older than MaxAllowedBuiltAge, and an offline scan would
	// then lose Grype entirely.
	installCfg.ValidateAge = false
	if a.DBUpdateCheckInterval > 0 {
		installCfg.UpdateCheckMaxFrequency = a.DBUpdateCheckInterval
	}

	client, err := v6dist.NewClient(distCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("distribution client: %w", err)
	}
	curator, err := v6inst.NewCurator(installCfg, client)
	if err != nil {
		return nil, nil, fmt.Errorf("database curator: %w", err)
	}

	if a.DisableDBUpdate {
		logger.Debug("Grype vulnerability DB update disabled; using the local copy as it is")
	} else {
		updated, err := curator.Update()
		switch {
		case err != nil:
			logger.Warn("Grype vulnerability DB update check failed; matching with the local copy", zap.Error(err))
		case updated:
			logger.Info(fmt.Sprintf("Grype vulnerability DB downloaded to %s", a.dbDir()))
		default:
			logger.Debug(fmt.Sprintf("Grype vulnerability DB is current, or was checked within the last %s", installCfg.UpdateCheckMaxFrequency))
		}
	}

	status := curator.Status()
	if status.Error != nil {
		return nil, nil, status.Error
	}
	reader, err := curator.Reader()
	if err != nil {
		return nil, nil, fmt.Errorf("database reader: %w", err)
	}
	return v6.NewVulnerabilityProvider(reader), &status, nil
}

// maxDBAge returns the configured staleness limit, or Grype's default.
func (a Matcher) maxDBAge() time.Duration {
	if a.DBMaxAge > 0 {
		return a.DBMaxAge
	}
	return defaultDBMaxAge
}

// reportDBAge logs when the database was built: at WARN, which Bomly shows
// without -v, once it is older than the limit, because every advisory
// published since is missing from this run's findings; at INFO otherwise.
func (a Matcher) reportDBAge(logger *zap.Logger, built, now time.Time) {
	age, stale := dbAge(built, now, a.maxDBAge())
	switch {
	case built.IsZero():
		logger.Debug("Grype vulnerability DB reports no build time")
	case stale:
		logger.Warn(fmt.Sprintf("Grype vulnerability DB was built %s ago, past the %s limit; advisories published since then are missing until a newer database downloads", formatAge(age), formatAge(a.maxDBAge())))
	default:
		logger.Info(fmt.Sprintf("Grype vulnerability DB built %s (%s ago)", built.UTC().Format(time.RFC3339), formatAge(age)))
	}
}

// dbAge returns how old a database built at the given time is, and whether
// that exceeds maxAge. A zero build time is never stale: there is nothing to
// measure.
func dbAge(built, now time.Time, maxAge time.Duration) (time.Duration, bool) {
	if built.IsZero() {
		return 0, false
	}
	age := now.Sub(built)
	return age, age > maxAge
}

// formatAge renders a database age in whole days once it is a day or more,
// and as a short duration below that.
func formatAge(value time.Duration) string {
	if value >= 24*time.Hour {
		return fmt.Sprintf("%dd", int(value.Hours()/24))
	}
	return formatDuration(value)
}

// graphPkgToGrypePkg builds a Grype package from a registry package, using the
// canonical PURL as the correlation ID so matches can be mapped back to the
// registry.
//
// The name must be the ecosystem-native one: Grype searches its DB strictly by
// the name it is handed and never reconstructs a namespace from the PURL
// (except for Java, where its own resolver does), so passing the bare Name
// would query "postcss" for "@tailwindcss/postcss" and attach every postcss
// advisory to the scoped package.
//
// Distro and upstream (origin) packages are derived from the PURL qualifiers
// Syft records for OS packages — Grype's OS matchers are distro-namespace
// driven and match nothing without them. See purl_builtin.go.
func graphPkgToGrypePkg(p *model.Package) grypepkg.Package {
	syftType := ecosystemToSyftType(string(p.Ecosystem))
	name := p.EcosystemName()
	return grypepkg.Package{
		ID:        grypepkg.ID(p.PURL),
		Name:      name,
		Version:   p.Version,
		PURL:      p.PURL,
		Type:      syftType,
		Language:  ecosystemToSyftLanguage(string(p.Ecosystem)),
		Distro:    distroFromPURL(p.PURL),
		Upstreams: upstreamsFromPURL(p.PURL, name, syftType),
	}
}

// supportedEcosystems lists what builtin mode can match. It mirrors the
// ecosystemToSyftType switch below: an ecosystem missing from that switch
// reaches Grype as an unknown package type and matches nothing, so declaring
// the set keeps the generated docs and `bomly plugins list` honest.
//
// This is every Bomly ecosystem Syft has a package type for. Only sbom (not a
// package ecosystem) and snap (no Syft type) are absent.
//
// The OS-level entries — alpm, apk, dpkg, rpm, portage, homebrew — are matched
// through Grype's distro-namespace matchers, which need the distro the package
// came from. graphPkgToGrypePkg derives it (plus the upstream source package)
// from the PURL qualifiers Syft records, so those ecosystems only match when
// the PURL carries a `distro=` qualifier — true for image scans and for SBOMs
// produced from one, not for a bare `pkg:apk/openssl@3.0.8-r0`.
var supportedEcosystems = []model.Ecosystem{
	model.EcosystemNPM,
	model.EcosystemMaven,
	model.EcosystemScala,
	model.EcosystemGo,
	model.EcosystemPython,
	model.EcosystemDotNet,
	model.EcosystemRuby,
	model.EcosystemRust,
	model.EcosystemDart,
	model.EcosystemElixir,
	model.EcosystemErlang,
	model.EcosystemPHP,
	model.EcosystemSwift,
	model.EcosystemHaskell,
	model.EcosystemR,
	model.EcosystemLua,
	model.EcosystemCPP,
	model.EcosystemOCaml,
	model.EcosystemProlog,
	model.EcosystemConda,
	model.EcosystemNix,
	model.EcosystemTerraform,
	model.EcosystemWordPress,
	model.EcosystemALPM,
	model.EcosystemAPK,
	model.EcosystemDPKG,
	model.EcosystemRPM,
	model.EcosystemPortage,
	model.EcosystemHomebrew,
	model.EcosystemGitHub,
}

func ecosystemToSyftType(ecosystem string) syftPkg.Type {
	switch strings.ToLower(ecosystem) {
	case "npm", "nodejs":
		return syftPkg.NpmPkg
	case "maven", "java", "gradle", "scala", "sbt":
		return syftPkg.JavaPkg
	case "go", "golang":
		return syftPkg.GoModulePkg
	case "python", "pypi":
		return syftPkg.PythonPkg
	case "dotnet", "nuget":
		return syftPkg.DotnetPkg
	case "ruby", "rubygems":
		return syftPkg.GemPkg
	case "rust", "cargo":
		return syftPkg.RustPkg
	case "rpm":
		return syftPkg.RpmPkg
	case "apk":
		return syftPkg.ApkPkg
	case "dpkg", "deb":
		return syftPkg.DebPkg
	case "dart":
		return syftPkg.DartPubPkg
	case "elixir", "erlang", "hex":
		return syftPkg.HexPkg
	case "php":
		return syftPkg.PhpComposerPkg
	case "swift":
		return syftPkg.SwiftPkg
	case "haskell":
		return syftPkg.HackagePkg
	case "r":
		return syftPkg.Rpkg
	case "lua":
		return syftPkg.LuaRocksPkg
	case "cpp", "conan":
		return syftPkg.ConanPkg
	case "ocaml", "opam":
		return syftPkg.OpamPkg
	case "prolog":
		return syftPkg.SwiplPackPkg
	case "alpm":
		return syftPkg.AlpmPkg
	case "conda":
		return syftPkg.CondaPkg
	case "nix":
		return syftPkg.NixPkg
	case "portage":
		return syftPkg.PortagePkg
	case "homebrew":
		return syftPkg.HomebrewPkg
	case "terraform":
		return syftPkg.TerraformPkg
	case "wordpress":
		return syftPkg.WordpressPluginPkg
	case "github-actions", "githubactions":
		return syftPkg.GithubActionPkg
	default:
		return syftPkg.UnknownPkg
	}
}

func ecosystemToSyftLanguage(ecosystem string) syftPkg.Language {
	switch strings.ToLower(ecosystem) {
	case "npm", "nodejs":
		return syftPkg.JavaScript
	case "maven", "java", "gradle", "scala", "sbt":
		return syftPkg.Java
	case "go", "golang":
		return syftPkg.Go
	case "python", "pypi":
		return syftPkg.Python
	case "dotnet", "nuget":
		return syftPkg.Dotnet
	case "ruby", "rubygems":
		return syftPkg.Ruby
	case "rust", "cargo":
		return syftPkg.Rust
	case "dart":
		return syftPkg.Dart
	case "elixir", "erlang", "hex":
		return syftPkg.Elixir
	case "php":
		return syftPkg.PHP
	case "swift":
		return syftPkg.Swift
	case "haskell":
		return syftPkg.Haskell
	case "r":
		return syftPkg.R
	case "lua":
		return syftPkg.Lua
	case "cpp", "conan":
		return syftPkg.CPP
	case "ocaml", "opam":
		return syftPkg.OCaml
	case "prolog":
		return syftPkg.Swipl
	default:
		// OS and platform package types (alpm, conda, nix, portage, homebrew,
		// terraform, wordpress, github-actions) have no Syft language — they
		// are matched by package type and distro namespace instead.
		return syftPkg.UnknownLanguage
	}
}

// applyMatches converts Grype match results into vulnerability enrichment on the
// PURL-keyed package registry. The Grype package ID was set to the canonical
// PURL by graphPkgToGrypePkg.
func applyMatches(matches *grypematch.Matches, registry *model.PackageRegistry) {
	if matches == nil || registry == nil {
		return
	}

	for _, m := range matches.Sorted() {
		purl := string(m.Package.ID)
		if purl == "" {
			purl = m.Package.PURL
		}
		if purl == "" {
			continue
		}
		pkg := registry.Ensure(purl)
		if pkg == nil {
			continue
		}
		pkg.Matched = true
		pkg.Vulnerabilities = appendOrMergeVulnerability(pkg.Vulnerabilities, mapBuiltinMatch(m))
	}
}

func grypeMatchCounts(matches *grypematch.Matches) (int, int) {
	if matches == nil {
		return 0, 0
	}
	seen := make(map[string]struct{})
	vulnerabilities := 0
	for _, m := range matches.Sorted() {
		purl := string(m.Package.ID)
		if purl == "" {
			purl = m.Package.PURL
		}
		if purl != "" {
			seen[purl] = struct{}{}
		}
		vulnerabilities++
	}
	return len(seen), vulnerabilities
}

func mapBuiltinMatch(m grypematch.Match) model.Vulnerability {
	vuln := m.Vulnerability
	advisory := grypeAdvisory{
		ID:                   vuln.ID,
		Namespace:            vuln.Namespace,
		FixedVersions:        append([]string(nil), vuln.Fix.Versions...),
		FixState:             model.FixState(vuln.Fix.State),
		AffectedVersionRange: constraintString(vuln.Constraint),
		CPEs:                 cpeStrings(vuln.CPEs),
	}
	if vuln.Metadata != nil {
		advisory.DataSource = vuln.Metadata.DataSource
		advisory.Namespace = firstNonEmpty(vuln.Metadata.Namespace, advisory.Namespace)
		advisory.Severity = vuln.Metadata.Severity
		advisory.SeveritySource = vuln.Metadata.Namespace
		advisory.Description = vuln.Metadata.Description
		advisory.URLs = append([]string(nil), vuln.Metadata.URLs...)
		advisory.CVSS = builtinCVSS(vuln.Metadata.Cvss)
		advisory.KnownExploited = builtinKnownExploited(vuln.Metadata.KnownExploited)
		advisory.EPSS = builtinEPSS(vuln.Metadata.EPSS)
		advisory.CWEs = builtinCWEs(vuln.Metadata.CWEs)
		advisory.RiskScore = vuln.Metadata.RiskScore()
	}
	for _, fix := range vuln.Fix.Available {
		advisory.FixAvailable = append(advisory.FixAvailable, model.FixAvailable{
			Version: fix.Version,
			Date:    dateString(fix.Date),
			Kind:    model.FixAvailableKind(fix.Kind),
		})
	}
	for _, advisoryRef := range vuln.Advisories {
		advisory.References = append(advisory.References, model.Reference{URL: advisoryRef.Link, Type: model.ReferenceTypeAdvisory})
	}
	for _, related := range vuln.RelatedVulnerabilities {
		if related.ID != "" {
			advisory.Aliases = append(advisory.Aliases, related.ID)
		}
	}
	return mapGrypeAdvisory(advisory)
}

func constraintString(constraint fmt.Stringer) string {
	if constraint == nil {
		return ""
	}
	return constraint.String()
}

func builtinCVSS(scores []grypevuln.Cvss) []model.CVSSScore {
	if len(scores) == 0 {
		return nil
	}
	out := make([]model.CVSSScore, 0, len(scores))
	for _, score := range scores {
		if score.Vector == "" && score.Metrics.BaseScore == 0 {
			continue
		}
		out = append(out, model.CVSSScore{
			Vector:  score.Vector,
			Score:   score.Metrics.BaseScore,
			Version: model.SeverityType(score.Version),
			Source:  score.Source,
		})
	}
	return out
}

func builtinKnownExploited(values []grypevuln.KnownExploited) []model.KnownExploited {
	if len(values) == 0 {
		return nil
	}
	out := make([]model.KnownExploited, 0, len(values))
	for _, value := range values {
		out = append(out, model.KnownExploited{
			CVE:                        value.CVE,
			VendorProject:              value.VendorProject,
			Product:                    value.Product,
			DateAdded:                  datePtrString(value.DateAdded),
			RequiredAction:             value.RequiredAction,
			DueDate:                    datePtrString(value.DueDate),
			KnownRansomwareCampaignUse: value.KnownRansomwareCampaignUse,
			Notes:                      value.Notes,
			URLs:                       append([]string(nil), value.URLs...),
			CWEs:                       append([]string(nil), value.CWEs...),
		})
	}
	return out
}

func builtinEPSS(values []grypevuln.EPSS) []model.EPSSScore {
	if len(values) == 0 {
		return nil
	}
	out := make([]model.EPSSScore, 0, len(values))
	for _, value := range values {
		out = append(out, model.EPSSScore{
			CVE:        value.CVE,
			EPSS:       value.EPSS,
			Percentile: value.Percentile,
			Date:       dateString(value.Date),
		})
	}
	return out
}

func builtinCWEs(values []grypevuln.CWE) []model.CWE {
	if len(values) == 0 {
		return nil
	}
	out := make([]model.CWE, 0, len(values))
	for _, value := range values {
		out = append(out, model.CWE{
			CVE:    value.CVE,
			ID:     value.CWE,
			Source: value.Source,
			Type:   value.Type,
		})
	}
	return out
}

func cpeStrings(values []cpe.CPE) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.Attributes.String())
	}
	return out
}

func dateString(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.DateOnly)
}

func datePtrString(value *time.Time) string {
	if value == nil {
		return ""
	}
	return dateString(*value)
}
