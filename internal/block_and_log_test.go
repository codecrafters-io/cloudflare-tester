package internal

import (
	"bytes"
	"net"
	"regexp"
	"testing"

	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
)

// A correct policy filter passes all three implemented stages.
func TestBlockAndLogPassAll(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testPolicyScenario(t, scenario, 0)
}

// An unfiltered proxy cannot pass the blocking checks.
func TestBlockAndLogPreviousStage(t *testing.T) {
	// Arrange
	scenario := "previous_stage"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// Forwarding before returning a denial leaks the blocked request.
func TestBlockAndLogLeakBeforeBlock(t *testing.T) {
	// Arrange
	scenario := "leak_before_block"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// Forwarding shortly after a denial is still detected as a leak.
func TestBlockAndLogLeakAfterBlock(t *testing.T) {
	// Arrange
	scenario := "leak_after_block"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// A denial must return HTTP 403.
func TestBlockAndLogWrongStatus(t *testing.T) {
	// Arrange
	scenario := "wrong_status"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// A denial must name the matching policy rule.
func TestBlockAndLogWrongRule(t *testing.T) {
	// Arrange
	scenario := "wrong_rule"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// A denial must contain a readable JSON API error.
func TestBlockAndLogInvalidError(t *testing.T) {
	// Arrange
	scenario := "invalid_error"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// Matches in conversation history are inspected too.
func TestBlockAndLogUserOnly(t *testing.T) {
	// Arrange
	scenario := "user_only"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// A term outside message content must not trigger a denial.
func TestBlockAndLogScanEnvelope(t *testing.T) {
	// Arrange
	scenario := "scan_envelope"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// Text in separate messages is not joined for matching.
func TestBlockAndLogJoinMessages(t *testing.T) {
	// Arrange
	scenario := "join_messages"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// Literal matching does not fold uppercase text.
func TestBlockAndLogLowerCase(t *testing.T) {
	// Arrange
	scenario := "lower_case"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// Log mode forwards matching requests instead of blocking them.
func TestBlockAndLogLogBlocks(t *testing.T) {
	// Arrange
	scenario := "log_blocks"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// A log-mode match names its rule in the response header.
func TestBlockAndLogNoMatchHeader(t *testing.T) {
	// Arrange
	scenario := "no_match_header"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// A clean response must not inherit an earlier match header.
func TestBlockAndLogStickyHeader(t *testing.T) {
	// Arrange
	scenario := "sticky_header"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// Inspection must preserve forwarded request bytes.
func TestBlockAndLogRewriteRequest(t *testing.T) {
	// Arrange
	scenario := "rewrite_request"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// A log-mode match must preserve the origin response bytes.
func TestBlockAndLogRewriteResponse(t *testing.T) {
	// Arrange
	scenario := "rewrite_response"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// Text inside content parts is inspected too.
func TestBlockAndLogSkipParts(t *testing.T) {
	// Arrange
	scenario := "skip_parts"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// Matching raw request bytes misses a term hidden by a JSON escape.
func TestBlockAndLogRawMatch(t *testing.T) {
	// Arrange
	scenario := "raw_match"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// A tool-call message with null content must not crash the firewall.
func TestBlockAndLogNullCrash(t *testing.T) {
	// Arrange
	scenario := "null_crash"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

// A request the firewall cannot inspect must not reach the origin.
func TestBlockAndLogForwardUninspectable(t *testing.T) {
	// Arrange
	scenario := "forward_uninspectable"
	// Act and Assert
	testPolicyScenario(t, scenario, 1)
}

func testPolicyScenario(t *testing.T, scenario string, exitCode int) {
	t.Helper()
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		scenario: {
			StageSlugs:          []string{"kg7", "tf0", "fi6"},
			CodePath:            "test_helpers/scenarios/base/block_and_log/" + scenario,
			ExpectedExitCode:    exitCode,
			StdoutFixturePath:   "test_helpers/fixtures/base/block_and_log/" + scenario,
			NormalizeOutputFunc: normalizePolicyOutput,
		},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080 after teardown: %v", err)
	}
	listener.Close()
}

var policyOrigin = regexp.MustCompile(`--origin (http://127\.0\.0\.1:[0-9]+)[^\n]*cloudflare-stage-3-`)
var policyPath = regexp.MustCompile(`/[^\s"]*/cloudflare-stage-3-[^/\s"]+/policy\.json`)

var policyCrashPeer = regexp.MustCompile(`(Exception occurred during processing of request from \('127\.0\.0\.1', )[0-9]+(\))`)

func normalizePolicyOutput(output []byte) []byte {
	output = policyCrashPeer.ReplaceAll(output, []byte(`${1}<client-port>${2}`))
	for _, match := range policyOrigin.FindAllSubmatch(output, -1) {
		output = bytes.ReplaceAll(output, match[1], []byte("<mock-origin>"))
		output = bytes.ReplaceAll(output, bytes.TrimPrefix(match[1], []byte("http://")), []byte("<mock-origin-host>"))
	}
	output = policyPath.ReplaceAll(output, []byte("<temporary-directory>/policy.json"))
	return normalizeProxyOutput(output)
}

// Normalization strips both allocated origins while retaining policy data and HTTP verdicts.
func TestPolicyOutputNormalization(t *testing.T) {
	// Arrange
	input := []byte("--origin http://127.0.0.1:45678 --detector http://127.0.0.1:8082 --policy \"/tmp/cloudflare-stage-3-123/policy.json\"\n--origin http://127.0.0.1:45679 --policy \"/tmp/cloudflare-stage-3-456/policy.json\"\nrule=deny-override HTTP 403 on port 8080 Host=127.0.0.1:45679\n")
	expected := "--origin <mock-origin> --detector http://127.0.0.1:8082 --policy \"<temporary-directory>/policy.json\"\n--origin <mock-origin> --policy \"<temporary-directory>/policy.json\"\nrule=deny-override HTTP 403 on port 8080 Host=<mock-origin-host>\n"
	// Act
	actual := string(normalizePolicyOutput(input))
	// Assert
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}
