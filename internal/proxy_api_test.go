package internal

import (
	"bytes"
	"net"
	"regexp"
	"testing"

	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
)

// A transparent proxy works with the official SDK and still passes stage 1.
func TestProxyAPISuccess(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testProxyScenario(t, scenario, 0)
}

// A health-check-only implementation does not pass the proxy stage.
func TestProxyAPIPreviousStage(t *testing.T) {
	// Arrange
	scenario := "stage1_only"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

// A firewall that never replies receives a bounded and useful timeout diagnostic.
func TestProxyAPITimeout(t *testing.T) {
	// Arrange
	scenario := "hang_request"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

// Dropping the request authentication header fails the stage.
func TestProxyAPIAuthorization(t *testing.T) {
	// Arrange
	scenario := "drop_authorization"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

// The forwarded Host header identifies the configured origin rather than the firewall.
func TestProxyAPIOriginHost(t *testing.T) {
	// Arrange
	scenario := "wrong_host"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

// Changing the request body is detected at the origin.
func TestProxyAPIRequestBody(t *testing.T) {
	// Arrange
	scenario := "change_request"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

// Dropping an extra response field fails the passthrough check.
func TestProxyAPIResponseBody(t *testing.T) {
	// Arrange
	scenario := "change_response"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

// Extra response bytes cannot pass as a valid relay.
func TestProxyAPIExtraResponse(t *testing.T) {
	// Arrange
	scenario := "extra_response"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

// The origin request ID must reach the client.
func TestProxyAPIResponseHeaders(t *testing.T) {
	// Arrange
	scenario := "drop_response_header"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

// An origin HTTP error keeps its original status.
func TestProxyAPIOriginError(t *testing.T) {
	// Arrange
	scenario := "convert_origin_error"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

// A connection failure must produce HTTP 502.
func TestProxyAPIUnavailableOrigin(t *testing.T) {
	// Arrange
	scenario := "wrong_gateway"
	// Act and Assert
	testProxyScenario(t, scenario, 1)
}

func testProxyScenario(t *testing.T, scenario string, exitCode int) {
	t.Helper()
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		scenario: {
			StageSlugs:          []string{"tf0", "fi6"},
			CodePath:            "test_helpers/scenarios/base/proxy_api/" + scenario,
			ExpectedExitCode:    exitCode,
			StdoutFixturePath:   "test_helpers/fixtures/base/proxy_api/" + scenario,
			NormalizeOutputFunc: normalizeProxyOutput,
		},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080 after teardown: %v", err)
	}
	listener.Close()
}

var proxyOrigin = regexp.MustCompile(`--origin (http://127\.0\.0\.1:[0-9]+)[^\n]*cloudflare-stage-2-`)
var proxyPolicyPath = regexp.MustCompile(`/[^\s"]*/cloudflare-stage-2-[^/\s"]+/policy\.json`)

func normalizeProxyOutput(output []byte) []byte {
	if match := proxyOrigin.FindSubmatch(output); len(match) > 1 {
		output = bytes.ReplaceAll(output, match[1], []byte("<mock-origin>"))
	}
	output = proxyPolicyPath.ReplaceAll(output, []byte("<temporary-directory>/policy.json"))
	return normalizeStage1Output(output)
}

// Normalization removes allocated addresses while preserving protocol constants and verdicts.
func TestProxyOutputNormalization(t *testing.T) {
	// Arrange
	input := []byte("--origin http://127.0.0.1:45678 --detector http://127.0.0.1:8082 --policy \"/tmp/cloudflare-stage-2-123/policy.json\"\nSDK http://127.0.0.1:8080/v1 returned HTTP 502\n")
	expected := "--origin <mock-origin> --detector http://127.0.0.1:8082 --policy \"<temporary-directory>/policy.json\"\nSDK http://127.0.0.1:8080/v1 returned HTTP 502\n"
	// Act
	actual := string(normalizeProxyOutput(input))
	// Assert
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}
