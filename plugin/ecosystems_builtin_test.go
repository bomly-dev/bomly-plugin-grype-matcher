//go:build !bomly_external_grype

package plugin

import (
	"testing"

	syftPkg "github.com/anchore/syft/syft/pkg"

	"github.com/bomly-dev/bomly-sdk/model"
)

// The declared ecosystem list is what the generated docs and `bomly plugins
// list` show, so it has to stay in step with what ecosystemToSyftType can
// actually map. This fails if a case is added to one without the other.
func TestSupportedEcosystemsMatchSyftTypeMapping(t *testing.T) {
	all := []model.Ecosystem{
		model.EcosystemNPM, model.EcosystemMaven, model.EcosystemGo, model.EcosystemPython,
		model.EcosystemALPM, model.EcosystemAPK, model.EcosystemCPP, model.EcosystemConda,
		model.EcosystemDart, model.EcosystemDPKG, model.EcosystemElixir, model.EcosystemErlang,
		model.EcosystemGitHub, model.EcosystemHaskell, model.EcosystemHomebrew, model.EcosystemLua,
		model.EcosystemDotNet, model.EcosystemNix, model.EcosystemOCaml, model.EcosystemPHP,
		model.EcosystemPortage, model.EcosystemProlog, model.EcosystemR, model.EcosystemRPM,
		model.EcosystemRuby, model.EcosystemRust, model.EcosystemScala, model.EcosystemSBOM,
		model.EcosystemSnap, model.EcosystemSwift, model.EcosystemTerraform,
		model.EcosystemWordPress, model.EcosystemOther,
	}

	declared := make(map[model.Ecosystem]bool, len(supportedEcosystems))
	for _, eco := range supportedEcosystems {
		declared[eco] = true
	}

	for _, eco := range all {
		mappable := ecosystemToSyftType(string(eco)) != syftPkg.UnknownPkg
		if mappable && !declared[eco] {
			t.Errorf("ecosystemToSyftType maps %q but supportedEcosystems omits it", eco)
		}
		if !mappable && declared[eco] {
			t.Errorf("supportedEcosystems declares %q but ecosystemToSyftType does not map it", eco)
		}
	}
}
