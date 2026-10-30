package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/mod/semver"
)

// anchoreApacheLicenseSHA256 is the SHA-256 of the LICENSE file Grype and
// Syft ship, Anchore's copy of the Apache-2.0 text. A relicense, or any
// edit to that file, changes it.
const anchoreApacheLicenseSHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"

// minGrypeVersion is the oldest Grype whose database schema Anchore still
// serves. Retiring schema v5 on 2026-03-06 cut off every client older than
// v0.88.0, and such a client fails silently: it reports no vulnerabilities
// rather than an error. Raise this when Anchore announces the next schema
// end of life.
const minGrypeVersion = "v0.88.0"

// TestUpstreamLicensesAreUnchanged fails a dependency bump that changes the
// licence of the Anchore libraries this matcher compiles in, so the change
// is read before it ships rather than found afterwards (bomly-planning#10).
func TestUpstreamLicensesAreUnchanged(t *testing.T) {
	for _, path := range []string{"github.com/anchore/grype", "github.com/anchore/syft"} {
		mod := upstreamModule(t, path)
		data, err := os.ReadFile(filepath.Join(mod.Dir, "LICENSE"))
		if err != nil {
			t.Fatalf("%s@%s: read LICENSE: %v", path, mod.Version, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != anchoreApacheLicenseSHA256 {
			t.Errorf("%s@%s: LICENSE changed (sha256 %s, want %s). Read %s/LICENSE: if it is still Apache-2.0, update anchoreApacheLicenseSHA256; if not, do not take this bump: open an issue, since the licence is part of what users accept with this plugin",
				path, mod.Version, got, anchoreApacheLicenseSHA256, mod.Dir)
		}
	}
}

// TestGrypeVersionMeetsSchemaFloor fails a pin older than the database schema
// floor, because such a Grype would match against nothing without saying so.
func TestGrypeVersionMeetsSchemaFloor(t *testing.T) {
	mod := upstreamModule(t, "github.com/anchore/grype")
	if semver.Compare(mod.Version, minGrypeVersion) < 0 {
		t.Errorf("github.com/anchore/grype is pinned at %s, below %s, the oldest version whose database schema Anchore still serves; such a Grype finds no vulnerabilities without reporting an error. Pin %s or later",
			mod.Version, minGrypeVersion, minGrypeVersion)
	}
}

// upstreamModule resolves the version and module-cache directory the build
// uses for path, as the go command reports them.
func upstreamModule(t *testing.T, path string) (mod struct{ Version, Dir string }) {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-json", path).Output()
	if err != nil {
		t.Fatalf("go list -m %s: %v", path, err)
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatalf("go list -m %s: decode: %v", path, err)
	}
	if mod.Version == "" || mod.Dir == "" {
		t.Fatalf("go list -m %s: no version or directory in %s", path, out)
	}
	return mod
}
