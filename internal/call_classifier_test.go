package internal

import (
	"bytes"
	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
	"net"
	"regexp"
	"testing"
)

// A classifier-aware firewall passes stage 6.
func TestCallClassifierPassAll(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testClassifierScenario(t, scenario, 0, false)
}

// The previous stage never calls the detector.
func TestCallClassifierPreviousStage(t *testing.T) {
	// Arrange
	scenario := "previous_stage"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// Five classifier calls must run in parallel.
func TestCallClassifierSequential(t *testing.T) {
	// Arrange
	scenario := "sequential"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// Every history message must reach the classifier.
func TestCallClassifierFirstMessageOnly(t *testing.T) {
	// Arrange
	scenario := "first_message_only"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// The classifier receives original message content.
func TestCallClassifierNormalizeDetectorInput(t *testing.T) {
	// Arrange
	scenario := "normalize_detector_input"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// Original message roles must reach the classifier.
func TestCallClassifierDropRole(t *testing.T) {
	// Arrange
	scenario := "drop_role"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// Origin credentials must not be sent to the classifier.
func TestCallClassifierLeakAuthorization(t *testing.T) {
	// Arrange
	scenario := "leak_authorization"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// Fail-open preserves heuristic decisions when classification fails.
func TestCallClassifierAlwaysClosed(t *testing.T) {
	// Arrange
	scenario := "always_closed"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// Fail-closed rejects unavailable classification.
func TestCallClassifierAlwaysOpen(t *testing.T) {
	// Arrange
	scenario := "always_open"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// Fail-open discards partial classifier results.
func TestCallClassifierKeepPartialScores(t *testing.T) {
	// Arrange
	scenario := "keep_partial_scores"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// A stalled classifier cannot hold a request open.
func TestCallClassifierNoTimeout(t *testing.T) {
	// Arrange
	scenario := "no_timeout"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// Executor shutdown must not wait past the classifier deadline.
func TestCallClassifierWaitOnShutdown(t *testing.T) {
	// Arrange
	scenario := "wait_on_shutdown"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// The classifier cutoff comes from the policy.
func TestCallClassifierHardcodedThreshold(t *testing.T) {
	// Arrange
	scenario := "hardcoded_threshold"
	// Act and Assert
	testClassifierScenario(t, scenario, 1, false)
}

// The classifier reference also preserves all five earlier stages.
func TestCallClassifierAllStages(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testClassifierScenario(t, scenario, 0, true)
}

func testClassifierScenario(t *testing.T, scenario string, exitCode int, allStages bool) {
	t.Helper()
	stages := []string{"xd5"}
	fixture := scenario
	if allStages {
		stages = append(stages, "ro3", "wt4", "kg7", "tf0", "fi6")
		fixture = "all_stages"
	}
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		fixture: {
			StageSlugs:          stages,
			CodePath:            "test_helpers/scenarios/base/call_classifier/" + scenario,
			ExpectedExitCode:    exitCode,
			StdoutFixturePath:   "test_helpers/fixtures/base/call_classifier/" + fixture,
			NormalizeOutputFunc: normalizeClassifierOutput,
		},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080 after teardown: %v", err)
	}
	listener.Close()
}

var classifierEndpoints = regexp.MustCompile(`--origin (http://127\.0\.0\.1:[0-9]+) --detector (http://127\.0\.0\.1:[0-9]+)[^\n]*cloudflare-stage-(?:[6789]|10|11)-`)
var classifierPath = regexp.MustCompile(`/[^\s"]*/cloudflare-stage-(?:[6789]|10|11)-[^/\s"]+/policy\.json`)
var classifierMeasurement = regexp.MustCompile(`(batch_ms|single_ms|elapsed_ms)=[0-9]+\.[0-9]+`)
var classifierParallelLimit = regexp.MustCompile(`(batch_ms=<measured> single_ms=<measured> limit_ms=)[0-9]+\.[0-9]+`)

func normalizeClassifierOutput(output []byte) []byte {
	for _, match := range classifierEndpoints.FindAllSubmatch(output, -1) {
		for index, name := range []string{"<mock-origin>", "<mock-detector>"} {
			output = bytes.ReplaceAll(output, match[index+1], []byte(name))
			output = bytes.ReplaceAll(output, bytes.TrimPrefix(match[index+1], []byte("http://")), []byte(name+"-host"))
		}
	}
	output = classifierPath.ReplaceAll(output, []byte("<temporary-directory>/policy.json"))
	output = classifierMeasurement.ReplaceAll(output, []byte("${1}=<measured>"))
	output = classifierParallelLimit.ReplaceAll(output, []byte("${1}<measured>"))
	return normalizeHeuristicOutput(output)
}

// Comparison normalization retains fixed deadline and failure evidence.
func TestClassifierOutputNormalization(t *testing.T) {
	// Arrange
	input := []byte("--origin http://127.0.0.1:45678 --detector http://127.0.0.1:45679 --policy \"/tmp/cloudflare-stage-6-123/policy.json\"\nbatch_ms=122.3 single_ms=123.1 limit_ms=246.2\nelapsed_ms=200.3 limit_ms=600.0 timeout 200ms HTTP 403 detector_unavailable\n")
	expected := "--origin <mock-origin> --detector <mock-detector> --policy \"<temporary-directory>/policy.json\"\nbatch_ms=<measured> single_ms=<measured> limit_ms=<measured>\nelapsed_ms=<measured> limit_ms=600.0 timeout 200ms HTTP 403 detector_unavailable\n"
	// Act
	actual := string(normalizeClassifierOutput(input))
	// Assert
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}
