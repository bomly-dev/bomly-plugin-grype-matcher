package plugin

import (
	"context"
	"fmt"
	"strings"

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
				return Matcher{
					DBDir:  strings.TrimSpace(raw.DBDir),
					Logger: host.Logger(),
				}, nil
			},
		},
	}
}
