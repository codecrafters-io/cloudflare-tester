package internal

import (
	"bytes"
	"net"
	"regexp"
	"testing"

	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
)

// A normalization-aware filter passes all four implemented stages.
func TestDefeatEvasionPassAll(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testEvasionScenario(t, scenario, 0)
}

// A literal filter misses a full-width prompt.
func TestDefeatEvasionPreviousStage(t *testing.T) {
	// Arrange
	scenario := "previous_stage"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Full-width letters require compatibility normalization.
func TestDefeatEvasionSkipNfkc(t *testing.T) {
	// Arrange
	scenario := "skip_nfkc"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Uppercase prompts require Unicode case folding.
func TestDefeatEvasionSkipCasefold(t *testing.T) {
	// Arrange
	scenario := "skip_casefold"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Lowercasing alone does not expand sharp s to ss.
func TestDefeatEvasionLowerOnly(t *testing.T) {
	// Arrange
	scenario := "lower_only"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Invisible characters must be removed using the policy list.
func TestDefeatEvasionSkipZeroWidth(t *testing.T) {
	// Arrange
	scenario := "skip_zero_width"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Cyrillic look-alikes must use the supplied mapping.
func TestDefeatEvasionSkipHomoglyphs(t *testing.T) {
	// Arrange
	scenario := "skip_homoglyphs"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// The log policy uses a different homoglyph mapping.
func TestDefeatEvasionHardcodedMap(t *testing.T) {
	// Arrange
	scenario := "hardcoded_map"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// A denied term inside one base64 layer must be inspected.
func TestDefeatEvasionSkipBase64(t *testing.T) {
	// Arrange
	scenario := "skip_base64"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Base64 is decoded before any case folding changes its bytes.
func TestDefeatEvasionFoldBeforeDecode(t *testing.T) {
	// Arrange
	scenario := "fold_before_decode"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Decoded Unicode text goes through the same normalization steps.
func TestDefeatEvasionSkipDecodedNormalization(t *testing.T) {
	// Arrange
	scenario := "skip_decoded_normalization"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Two base64 layers are outside the one-layer inspection limit.
func TestDefeatEvasionRecursiveDecode(t *testing.T) {
	// Arrange
	scenario := "recursive_decode"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Removing zero-width characters after NFKC leaves an accent uncomposed.
func TestDefeatEvasionZeroWidthAfterNfkc(t *testing.T) {
	// Arrange
	scenario := "zero_width_after_nfkc"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Rejecting noncanonical base64 skips text that decodes to a denied term.
func TestDefeatEvasionCanonicalBase64(t *testing.T) {
	// Arrange
	scenario := "canonical_base64"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

// Normalized inspection must not rewrite forwarded request bytes.
func TestDefeatEvasionRewriteRequest(t *testing.T) {
	// Arrange
	scenario := "rewrite_request"
	// Act and Assert
	testEvasionScenario(t, scenario, 1)
}

func testEvasionScenario(t *testing.T, scenario string, exitCode int) {
	t.Helper()
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		scenario: {
			StageSlugs:          []string{"wt4", "kg7", "tf0", "fi6"},
			CodePath:            "test_helpers/scenarios/base/defeat_evasion/" + scenario,
			ExpectedExitCode:    exitCode,
			StdoutFixturePath:   "test_helpers/fixtures/base/defeat_evasion/" + scenario,
			NormalizeOutputFunc: normalizeEvasionOutput,
		},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080 after teardown: %v", err)
	}
	listener.Close()
}

var evasionOrigin = regexp.MustCompile(`--origin (http://127\.0\.0\.1:[0-9]+)[^\n]*cloudflare-stage-4-`)
var evasionPath = regexp.MustCompile(`/[^\s"]*/cloudflare-stage-4-[^/\s"]+/policy\.json`)

func normalizeEvasionOutput(output []byte) []byte {
	for _, match := range evasionOrigin.FindAllSubmatch(output, -1) {
		output = bytes.ReplaceAll(output, match[1], []byte("<mock-origin>"))
		output = bytes.ReplaceAll(output, bytes.TrimPrefix(match[1], []byte("http://")), []byte("<mock-origin-host>"))
	}
	output = evasionPath.ReplaceAll(output, []byte("<temporary-directory>/policy.json"))
	return normalizePolicyOutput(output)
}

// Comparison normalization preserves evasion evidence and rule verdicts.
func TestEvasionOutputNormalization(t *testing.T) {
	// Arrange
	input := []byte("--origin http://127.0.0.1:45678 --policy \"/tmp/cloudflare-stage-4-123/policy.json\"\nHost=127.0.0.1:45678 rule=deny-fold HTTP 403 \\u200b STRASSE\n")
	expected := "--origin <mock-origin> --policy \"<temporary-directory>/policy.json\"\nHost=<mock-origin-host> rule=deny-fold HTTP 403 \\u200b STRASSE\n"
	// Act
	actual := string(normalizeEvasionOutput(input))
	// Assert
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}
