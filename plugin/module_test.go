package plugin

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-sdk/conformance"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/httpkit"
	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// testHost is a minimal HostContext for unit tests.
type testHost struct {
	config json.RawMessage
}

func (h testHost) Logger() *zap.Logger                 { return zap.NewNop() }
func (h testHost) HTTPClient() *httpkit.ClientProvider { return nil }
func (h testHost) Runtime() sdkplugin.RuntimeInfo {
	return sdkplugin.RuntimeInfo{Execution: sdkplugin.ExecutionEmbedded}
}

func (h testHost) OnCleanup(func() error) {}

func (h testHost) DecodeConfig(v any) error {
	payload := h.config
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	return json.Unmarshal(payload, v)
}

// TestModuleConstructsMatcher checks the managed constructor produces the
// same Matcher shape the Bomly CLI composition constructs (Matcher{Logger})
// and honors the optional db_dir override.
func TestModuleConstructsMatcher(t *testing.T) {
	dbDir := filepath.Join(t.TempDir(), "db")
	cfg, err := json.Marshal(map[string]string{"db_dir": dbDir})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	component, err := Module().Matcher.New(context.Background(), testHost{config: cfg})
	if err != nil {
		t.Fatalf("construct matcher: %v", err)
	}
	matcher, ok := component.(Matcher)
	if !ok {
		t.Fatalf("unexpected component type %T", component)
	}
	if matcher.DBDir != dbDir {
		t.Fatalf("db dir = %q, want %q", matcher.DBDir, dbDir)
	}
	if matcher.Logger == nil {
		t.Fatal("expected logger to be injected")
	}
	if matcher.DisableDBUpdate {
		t.Fatal("db_auto_update defaults to true")
	}
	if matcher.DBMaxAge != 0 || matcher.DBUpdateCheckInterval != 0 {
		t.Fatalf("unset durations must stay zero (library defaults), got max age %s, check interval %s", matcher.DBMaxAge, matcher.DBUpdateCheckInterval)
	}
}

// TestModuleDecodesDBFreshnessConfig covers the managed-execution keys that
// control the database refresh: the opt-out, the staleness limit, and the
// update-check interval, plus the rejection of a malformed duration.
func TestModuleDecodesDBFreshnessConfig(t *testing.T) {
	cfg := json.RawMessage(`{"db_auto_update": false, "db_max_age": "48h", "db_update_check_interval": "30m"}`)
	component, err := Module().Matcher.New(context.Background(), testHost{config: cfg})
	if err != nil {
		t.Fatalf("construct matcher: %v", err)
	}
	matcher := component.(Matcher)
	if !matcher.DisableDBUpdate {
		t.Fatal("db_auto_update=false should disable the update check")
	}
	if matcher.DBMaxAge != 48*time.Hour {
		t.Fatalf("db_max_age = %s, want 48h", matcher.DBMaxAge)
	}
	if matcher.DBUpdateCheckInterval != 30*time.Minute {
		t.Fatalf("db_update_check_interval = %s, want 30m", matcher.DBUpdateCheckInterval)
	}

	_, err = Module().Matcher.New(context.Background(), testHost{config: json.RawMessage(`{"db_max_age": "five days"}`)})
	if err == nil || !strings.Contains(err.Error(), "db_max_age") {
		t.Fatalf("expected a db_max_age parse error, got %v", err)
	}
}

// TestDescriptorDoesNotAdvertisePackageUpdates pins the deliberate decision
// to stay on the in-place registry protocol: this matcher merges advisories
// into existing vulnerabilities field by field, which Package.MergeFrom
// cannot reproduce (see the Descriptor comment in matcher.go).
func TestDescriptorDoesNotAdvertisePackageUpdates(t *testing.T) {
	for _, capability := range (Matcher{}).Descriptor().Capabilities {
		if capability == sdkplugin.CapabilityPackageUpdates {
			t.Fatal("grype matcher must not advertise the package-updates capability; its vulnerability merge is not MergeFrom-expressible")
		}
	}
}

// TestConformance runs the SDK conformance suite against the module,
// including the bomly-plugin.json identity cross-check.
func TestConformance(t *testing.T) {
	conformance.Test(t, conformance.Config{
		Module:       Module(),
		ManifestPath: filepath.Join("..", "bomly-plugin.json"),
		SampleConfig: json.RawMessage(`{"db_dir":""}`),
	})
}

// TestProbeBinary builds the real plugin binary and probes it over the
// managed HashiCorp gRPC transport, asserting the served descriptor equals
// the in-process one. The binary is built with the same build tags as the
// running test so both variants stay probeable.
func TestProbeBinary(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available; skipping managed-transport probe")
	}
	binaryPath := filepath.Join(t.TempDir(), "bomly-plugin-grype-matcher")
	args := []string{"build"}
	if !builtinVariant {
		args = append(args, "-tags", "bomly_external_grype")
	}
	args = append(args, "-o", binaryPath, "./cmd/bomly-plugin-grype-matcher")
	build := exec.Command(goBinary, args...)
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build plugin binary: %v\n%s", err, output)
	}
	conformance.ProbeBinary(t, binaryPath, conformance.WithModule(Module()))
}
