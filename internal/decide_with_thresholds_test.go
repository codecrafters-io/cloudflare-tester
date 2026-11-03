package internal

import (
	"encoding/json"
	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
	"net"
	"reflect"
	"testing"
)

// The combined-decision reference passes stage 7.
func TestDecideWithThresholdsPassAll(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testThresholdScenario(t, scenario, 0, false)
}

// The old single cutoff still blocks the deliberate false positive.
func TestDecideWithThresholdsPreviousStage(t *testing.T) {
	// Arrange
	scenario := "previous_stage"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Both moderate scores are needed for the combined rule.
func TestDecideWithThresholdsOrInsteadOfAnd(t *testing.T) {
	// Arrange
	scenario := "or_instead_of_and"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Tool output uses stricter thresholds.
func TestDecideWithThresholdsIgnoreToolRole(t *testing.T) {
	// Arrange
	scenario := "ignore_tool_role"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Ordinary user text keeps the default thresholds.
func TestDecideWithThresholdsToolForAllRoles(t *testing.T) {
	// Arrange
	scenario := "tool_for_all_roles"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Heuristic evidence cannot be borrowed from another message.
func TestDecideWithThresholdsRequestWideHeuristics(t *testing.T) {
	// Arrange
	scenario := "request_wide_heuristics"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// A message cannot borrow another message classifier score.
func TestDecideWithThresholdsClassifierMax(t *testing.T) {
	// Arrange
	scenario := "classifier_max"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// A signal can contribute independently to each message.
func TestDecideWithThresholdsGlobalSignalCounts(t *testing.T) {
	// Arrange
	scenario := "global_signal_counts"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Classifier results remain paired with their original messages.
func TestDecideWithThresholdsArrivalOrder(t *testing.T) {
	// Arrange
	scenario := "arrival_order"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Successful combined decisions replace the old heuristic-only cutoff.
func TestDecideWithThresholdsKeepHeuristicCutoff(t *testing.T) {
	// Arrange
	scenario := "keep_heuristic_cutoff"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Successful combined decisions replace the old classifier-only cutoff.
func TestDecideWithThresholdsKeepClassifierCutoff(t *testing.T) {
	// Arrange
	scenario := "keep_classifier_cutoff"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Per-message heuristic scoring uses normalized and decoded text.
func TestDecideWithThresholdsSkipMessageNormalization(t *testing.T) {
	// Arrange
	scenario := "skip_message_normalization"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Both threshold tables come from the supplied policy.
func TestDecideWithThresholdsHardcodedThresholds(t *testing.T) {
	// Arrange
	scenario := "hardcoded_thresholds"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// The classifier high cutoff is inclusive.
func TestDecideWithThresholdsStrictHigh(t *testing.T) {
	// Arrange
	scenario := "strict_high"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// The classifier medium cutoff is inclusive.
func TestDecideWithThresholdsStrictClassifierMedium(t *testing.T) {
	// Arrange
	scenario := "strict_classifier_medium"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// The heuristic medium cutoff is inclusive.
func TestDecideWithThresholdsStrictHeuristicMedium(t *testing.T) {
	// Arrange
	scenario := "strict_heuristic_medium"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Log mode forwards combined matches unchanged.
func TestDecideWithThresholdsLogBlocks(t *testing.T) {
	// Arrange
	scenario := "log_blocks"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// Fail-open retains the earlier heuristic fallback rule.
func TestDecideWithThresholdsFallbackIgnoresHeuristics(t *testing.T) {
	// Arrange
	scenario := "fallback_ignores_heuristics"
	// Act and Assert
	testThresholdScenario(t, scenario, 1, false)
}

// The threshold reference preserves all six earlier stages.
func TestDecideWithThresholdsAllStages(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testThresholdScenario(t, scenario, 0, true)
}

func testThresholdScenario(t *testing.T, scenario string, exitCode int, allStages bool) {
	t.Helper()
	stages := []string{"si3"}
	fixture := scenario
	if allStages {
		stages = append(stages, "xd5", "ro3", "wt4", "kg7", "tf0", "fi6")
		fixture = "all_stages"
	}
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		fixture: {
			StageSlugs:          stages,
			CodePath:            "test_helpers/scenarios/base/decide_with_thresholds/" + scenario,
			ExpectedExitCode:    exitCode,
			StdoutFixturePath:   "test_helpers/fixtures/base/decide_with_thresholds/" + fixture,
			NormalizeOutputFunc: normalizeClassifierOutput,
		},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080 after teardown: %v", err)
	}
	listener.Close()
}

// Threshold policies preserve earlier detector settings and use the supplied tables.
func TestDecisionPolicyPreservesEarlierSettings(t *testing.T) {
	// Arrange
	var expected map[string]any
	if err := json.Unmarshal([]byte(classifierPolicyJSON("log", "fail_closed", 70)), &expected); err != nil {
		t.Fatal(err)
	}
	expected["decisions"] = map[string]any{
		"default": map[string]any{"classifier_high": float64(96), "classifier_medium": float64(75), "heuristic_medium": float64(4)},
		"tool":    map[string]any{"classifier_high": float64(88), "classifier_medium": float64(65), "heuristic_medium": float64(3)},
	}
	supplied := `{"default":{"classifier_high":96,"classifier_medium":75,"heuristic_medium":4},"tool":{"classifier_high":88,"classifier_medium":65,"heuristic_medium":3}}`
	// Act
	var actual map[string]any
	err := json.Unmarshal([]byte(decisionPolicyJSON("log", "fail_closed", supplied)), &actual)
	// Assert
	if err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("unexpected decision policy %v, err=%v", actual, err)
	}
}

// Threshold output comparison hides allocated addresses while retaining decision evidence.
func TestDecisionOutputNormalization(t *testing.T) {
	// Arrange
	input := []byte("--origin http://127.0.0.1:45678 --detector http://127.0.0.1:45679 --policy \"/tmp/cloudflare-stage-7-123/policy.json\"\nHTTP 403 combined_scores role=tool cutoff=40 timeout 200ms\n")
	expected := "--origin <mock-origin> --detector <mock-detector> --policy \"<temporary-directory>/policy.json\"\nHTTP 403 combined_scores role=tool cutoff=40 timeout 200ms\n"
	// Act
	actual := string(normalizeClassifierOutput(input))
	// Assert
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}
