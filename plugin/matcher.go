// Package grype implements a Matcher that uses the Grype vulnerability library
// (builtin) or the grype CLI binary (external), selected via build tags.
package plugin

import (
	"context"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// matcherName labels this matcher in stats and descriptors. It equals Name,
// the plugin identity.
const matcherName = Name

// Matcher uses the Grype library or CLI to match packages against a vulnerability database.
type Matcher struct {
	// DBDir is the directory that contains the Grype vulnerability database.
	// Defaults to the OS cache directory / grype / db.
	DBDir string
	// Logger receives diagnostic messages. Maybe nil (no-op).
	Logger *zap.Logger
	// DistConfigOverride overrides the default distribution config (e.g., LatestURL).
	DistConfigOverride any
}

func appendOrMergeVulnerability(existing []model.Vulnerability, entry model.Vulnerability) []model.Vulnerability {
	for idx, vulnerability := range existing {
		if vulnerability.Source == entry.Source && vulnerability.ID == entry.ID {
			existing[idx] = mergePackageVulnerability(vulnerability, entry)
			return existing
		}
	}
	return append(existing, entry)
}

// Descriptor returns the registration metadata for the Grype matcher.
func (a Matcher) Descriptor() sdkplugin.MatcherDescriptor {
	return sdkplugin.MatcherDescriptor{
		Name:        matcherName,
		DisplayName: displayName,
		// The package-updates delta protocol is deliberately NOT adopted.
		// This matcher merges a new advisory into an existing vulnerability
		// with the same (Source, ID) field by field — filling empty scalars
		// and unioning CVSS scores, references, aliases, EPSS, CWEs, and fix
		// data (see appendOrMergeVulnerability / mergePackageVulnerability).
		// Package.MergeFrom cannot express that: when a delta carries a
		// vulnerability whose (Source, ID) already exists on the target
		// package, it only fills Reachability and AffectedSymbols and drops
		// every other enrichment. Until the host merge grows field-level
		// vulnerability merging, only the in-place registry path preserves
		// this matcher's semantics.
		// Build-tag specific: builtin mode maps a fixed set of ecosystems onto
		// Syft package types, while external mode hands the graph to the grype
		// CLI and is unbounded. See supportedEcosystems in builtin.go and
		// external.go.
		SupportedEcosystems: supportedEcosystems,
	}
}

func (a Matcher) dbExists() bool {
	info, err := os.Stat(a.dbDir())
	return err == nil && info.IsDir()
}

func (a Matcher) Applicable(_ context.Context, _ sdkplugin.MatchRequest) (bool, error) {
	return true, nil
}

func (a Matcher) dbDir() string {
	if a.DBDir != "" {
		return a.DBDir
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(".cache", "grype", "db")
	}
	return filepath.Join(cacheDir, "grype", "db")
}

func (a Matcher) logger() *zap.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return zap.NewNop()
}

func grypeMatcherStats(matchedPackages, unmatchedPackages, vulnerabilities int) sdkplugin.MatcherStats {
	if unmatchedPackages < 0 {
		unmatchedPackages = 0
	}
	return sdkplugin.MatcherStats{
		Name:              matcherName,
		DisplayName:       displayName,
		MatchedPackages:   matchedPackages,
		UnmatchedPackages: unmatchedPackages,
		Vulnerabilities:   vulnerabilities,
	}
}
