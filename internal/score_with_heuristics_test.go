package internal

import (
	"bytes"
	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
	"net"
	"net/http"
	"regexp"
	"testing"
)

// The scoring reference passes all five stages.
func TestScoreWithHeuristicsPassAll(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testHeuristicScenario(t, scenario, 0)
}

// The previous stage cannot report or enforce heuristic scores.
func TestScoreWithHeuristicsPreviousStage(t *testing.T) {
	// Arrange
	scenario := "previous_stage"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// A weak signal alone stays below the cutoff.
func TestScoreWithHeuristicsAnySignalBlocks(t *testing.T) {
	// Arrange
	scenario := "any_signal_blocks"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// Signals contribute a sum rather than just the largest weight.
func TestScoreWithHeuristicsMaximumWeight(t *testing.T) {
	// Arrange
	scenario := "maximum_weight"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// A repeated signal contributes only once per request.
func TestScoreWithHeuristicsRepeatWeight(t *testing.T) {
	// Arrange
	scenario := "repeat_weight"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// A score equal to the threshold blocks.
func TestScoreWithHeuristicsStrictThreshold(t *testing.T) {
	// Arrange
	scenario := "strict_threshold"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// Words farther apart than the policy window do not match.
func TestScoreWithHeuristicsNearUnbounded(t *testing.T) {
	// Arrange
	scenario := "near_unbounded"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// A later occurrence can satisfy proximity.
func TestScoreWithHeuristicsNearFirstOnly(t *testing.T) {
	// Arrange
	scenario := "near_first_only"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// Proximity counts Unicode characters instead of UTF-8 bytes.
func TestScoreWithHeuristicsNearBytes(t *testing.T) {
	// Arrange
	scenario := "near_bytes"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// Proximity cannot bridge messages or text parts.
func TestScoreWithHeuristicsJoinTexts(t *testing.T) {
	// Arrange
	scenario := "join_texts"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// Signals inspect the normalized candidates from earlier stages.
func TestScoreWithHeuristicsSkipNormalization(t *testing.T) {
	// Arrange
	scenario := "skip_normalization"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// Signals and weights must come from the supplied policy.
func TestScoreWithHeuristicsHardcodedPolicy(t *testing.T) {
	// Arrange
	scenario := "hardcoded_policy"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// Log mode forwards a scored attack unchanged.
func TestScoreWithHeuristicsLogBlocks(t *testing.T) {
	// Arrange
	scenario := "log_blocks"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

// Each fired signal appears only once in the response.
func TestScoreWithHeuristicsDuplicateSignal(t *testing.T) {
	// Arrange
	scenario := "duplicate_signal"
	// Act and Assert
	testHeuristicScenario(t, scenario, 1)
}

func testHeuristicScenario(t *testing.T, scenario string, exitCode int) {
	t.Helper()
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		scenario: {
			StageSlugs:          []string{"ro3", "wt4", "kg7", "tf0", "fi6"},
			CodePath:            "test_helpers/scenarios/base/score_with_heuristics/" + scenario,
			ExpectedExitCode:    exitCode,
			StdoutFixturePath:   "test_helpers/fixtures/base/score_with_heuristics/" + scenario,
			NormalizeOutputFunc: normalizeHeuristicOutput,
		},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080 after teardown: %v", err)
	}
	listener.Close()
}

var heuristicOrigin = regexp.MustCompile(`--origin (http://127\.0\.0\.1:[0-9]+)[^\n]*firewall-stage-5-`)
var heuristicPath = regexp.MustCompile(`/[^\s"]*/firewall-stage-5-[^/\s"]+/policy\.json`)

func normalizeHeuristicOutput(output []byte) []byte {
	for _, match := range heuristicOrigin.FindAllSubmatch(output, -1) {
		output = bytes.ReplaceAll(output, match[1], []byte("<mock-origin>"))
		output = bytes.ReplaceAll(output, bytes.TrimPrefix(match[1], []byte("http://")), []byte("<mock-origin-host>"))
	}
	output = heuristicPath.ReplaceAll(output, []byte("<temporary-directory>/policy.json"))
	return normalizeEvasionOutput(output)
}

// Output normalization retains signal and score diagnostics.
func TestHeuristicOutputNormalization(t *testing.T) {
	// Arrange
	input := []byte("--origin http://127.0.0.1:45678 --policy \"/tmp/firewall-stage-5-123/policy.json\"\nHost=127.0.0.1:45678 score >= 5: true signals=[role-token]\n")
	expected := "--origin <mock-origin> --policy \"<temporary-directory>/policy.json\"\nHost=<mock-origin-host> score >= 5: true signals=[role-token]\n"
	// Act
	actual := string(normalizeHeuristicOutput(input))
	// Assert
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}

// Signal order and header whitespace do not affect set comparison.
func TestHeuristicHeadersAcceptReorderedIDs(t *testing.T) {
	// Arrange
	headers := http.Header{"X-Firewall-Signals": {" b, a "}, "X-Firewall-Score": {"8"}}
	// Act
	err := checkHeuristicHeaders(headers, heuristicExpectation{[]string{"a", "b"}, 5, true})
	// Assert
	if err != nil {
		t.Fatal(err)
	}
}

// Repeated IDs must not pass as a set.
func TestHeuristicHeadersRejectDuplicateIDs(t *testing.T) {
	// Arrange
	headers := http.Header{"X-Firewall-Signals": {"a,a"}, "X-Firewall-Score": {"8"}}
	// Act
	err := checkHeuristicHeaders(headers, heuristicExpectation{[]string{"a"}, 5, true})
	// Assert
	if err == nil {
		t.Fatal("expected invalid heuristic headers to fail")
	}
}

// A missing fired signal is rejected.
func TestHeuristicHeadersRejectMissingSignal(t *testing.T) {
	// Arrange
	headers := http.Header{"X-Firewall-Signals": {"a"}, "X-Firewall-Score": {"8"}}
	// Act
	err := checkHeuristicHeaders(headers, heuristicExpectation{[]string{"a", "b"}, 5, true})
	// Assert
	if err == nil {
		t.Fatal("expected invalid heuristic headers to fail")
	}
}

// An extra signal is rejected.
func TestHeuristicHeadersRejectExtraSignal(t *testing.T) {
	// Arrange
	headers := http.Header{"X-Firewall-Signals": {"a,b"}, "X-Firewall-Score": {"8"}}
	// Act
	err := checkHeuristicHeaders(headers, heuristicExpectation{[]string{"a"}, 5, true})
	// Assert
	if err == nil {
		t.Fatal("expected invalid heuristic headers to fail")
	}
}

// Nonnumeric scores are rejected.
func TestHeuristicHeadersRejectInvalidScore(t *testing.T) {
	// Arrange
	headers := http.Header{"X-Firewall-Signals": {"a"}, "X-Firewall-Score": {"NaN"}}
	// Act
	err := checkHeuristicHeaders(headers, heuristicExpectation{[]string{"a"}, 5, true})
	// Assert
	if err == nil {
		t.Fatal("expected invalid heuristic headers to fail")
	}
}

// Negative scores are rejected.
func TestHeuristicHeadersRejectNegativeScore(t *testing.T) {
	// Arrange
	headers := http.Header{"X-Firewall-Signals": {"a"}, "X-Firewall-Score": {"-1"}}
	// Act
	err := checkHeuristicHeaders(headers, heuristicExpectation{[]string{"a"}, 5, false})
	// Assert
	if err == nil {
		t.Fatal("expected invalid heuristic headers to fail")
	}
}

// A fired positive-weight signal cannot have a zero score.
func TestHeuristicHeadersRejectZeroWithSignals(t *testing.T) {
	// Arrange
	headers := http.Header{"X-Firewall-Signals": {"a"}, "X-Firewall-Score": {"0"}}
	// Act
	err := checkHeuristicHeaders(headers, heuristicExpectation{[]string{"a"}, 5, false})
	// Assert
	if err == nil {
		t.Fatal("expected invalid heuristic headers to fail")
	}
}

// An empty signal set must have a zero score.
func TestHeuristicHeadersRejectNonzeroWithoutSignals(t *testing.T) {
	// Arrange
	headers := http.Header{"X-Firewall-Signals": {}, "X-Firewall-Score": {"2"}}
	// Act
	err := checkHeuristicHeaders(headers, heuristicExpectation{nil, 5, false})
	// Assert
	if err == nil {
		t.Fatal("expected invalid heuristic headers to fail")
	}
}

// The score must be on the expected side of the threshold.
func TestHeuristicHeadersRejectWrongThresholdSide(t *testing.T) {
	// Arrange
	headers := http.Header{"X-Firewall-Signals": {"a"}, "X-Firewall-Score": {"4"}}
	// Act
	err := checkHeuristicHeaders(headers, heuristicExpectation{[]string{"a"}, 5, true})
	// Assert
	if err == nil {
		t.Fatal("expected invalid heuristic headers to fail")
	}
}
