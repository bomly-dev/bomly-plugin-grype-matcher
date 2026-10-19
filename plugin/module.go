package plugin

import (
	"context"
	"fmt"
	"strings"
	"time"

	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// Name is the plugin's identity. It MUST equal the "id" field in
// bomly-plugin.json — Bomly refuses to load a plugin whose manifest id and
// runtime descriptor name disagree. It is also the descriptor name the Bomly
// CLI composition keys on when it embeds this matcher.
const Name = "grype"

// displayName is the human-readable matcher name.
const displayName = "Grype"

// moduleConfig is the JSON configuration accepted in managed execution under
// plugins.matchers.grype.
type moduleConfig struct {
	// DBDir overrides the Grype vulnerability database directory. Defaults to
	// the OS cache directory / grype / db.
	DBDir string `json:"db_dir"`
	// DBAutoUpdate controls whether the builtin variant checks Grype's
	// distribution service for a newer database and downloads it. Defaults
	// to true; false uses the local copy as it is.
	DBAutoUpdate *bool `json:"db_auto_update"`
	// DBMaxAge is a Go duration (for example "120h") past which the builtin
	// variant warns that its database is stale. Defaults to 120h, five days.
	DBMaxAge string `json:"db_max_age"`
	// DBUpdateCheckInterval is a Go duration bounding how often the builtin
	// variant checks for a newer database. Defaults to 2h.
	DBUpdateCheckInterval string `json:"db_update_check_interval"`
}

// parseOptionalDuration parses a configured duration, treating an empty
// value as "use the default".
func parseOptionalDuration(key, raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if value < 0 {
		return 0, fmt.Errorf("%s: must not be negative, got %s", key, raw)
	}
	return value, nil
}

// moduleDescriptor is the matcher's static registration data, shared by the
// embedded Descriptor method and the managed Module constructor.
func moduleDescriptor() sdkplugin.MatcherDescriptor {
	descriptor := Matcher{}.Descriptor()
	descriptor.ConfigSchema = sdkplugin.MustConfigSchemaFor(moduleConfig{})
	return descriptor
}

// Module packages the matcher for both execution modes: Bomly can embed it
// in-process (the CLI composition constructs Matcher{Logger: ...} directly)
// or serve it as a managed plugin subprocess (see cmd/bomly-plugin-grype-matcher).
func Module() sdkplugin.Module {
	return sdkplugin.Module{
		Kind: sdkplugin.PluginKindMatcher,
		Matcher: &sdkplugin.MatcherModule{
			Descriptor: moduleDescriptor(),
			New: func(_ context.Context, host sdkplugin.HostContext) (sdkplugin.Matcher, error) {
				var raw moduleConfig
				if err := host.DecodeConfig(&raw); err != nil {
					return nil, fmt.Errorf("decode grype matcher configuration: %w", err)
				}
				maxAge, err := parseOptionalDuration("db_max_age", raw.DBMaxAge)
				if err != nil {
					return nil, fmt.Errorf("grype matcher configuration: %w", err)
				}
				checkInterval, err := parseOptionalDuration("db_update_check_interval", raw.DBUpdateCheckInterval)
				if err != nil {
					return nil, fmt.Errorf("grype matcher configuration: %w", err)
				}
				return Matcher{
					DBDir:                 strings.TrimSpace(raw.DBDir),
					Logger:                host.Logger(),
					DisableDBUpdate:       raw.DBAutoUpdate != nil && !*raw.DBAutoUpdate,
					DBMaxAge:              maxAge,
					DBUpdateCheckInterval: checkInterval,
				}, nil
			},
		},
	}
}
