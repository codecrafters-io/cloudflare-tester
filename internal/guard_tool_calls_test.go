package internal

import (
	"encoding/json"
	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
	"github.com/openai/openai-go/v3"
	"net"
	"strings"
	"testing"
)

// The tool-guard reference passes stage 10.
func TestGuardToolCallsPassAll(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testToolScenario(t, scenario, 0, false)
}

// The earlier implementation exposes unlisted actions.
func TestGuardToolCallsPreviousStage(t *testing.T) {
	// Arrange
	scenario := "previous_stage"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Tool names require trusted policy authorization.
func TestGuardToolCallsSkipTools(t *testing.T) {
	// Arrange
	scenario := "skip_tools"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Allowed hostnames match exactly rather than by substring.
func TestGuardToolCallsSubstringHost(t *testing.T) {
	// Arrange
	scenario := "substring_host"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// URL user information is not its destination hostname.
func TestGuardToolCallsUserinfoAsHost(t *testing.T) {
	// Arrange
	scenario := "userinfo_as_host"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Tool names remain case-sensitive.
func TestGuardToolCallsCasefoldNames(t *testing.T) {
	// Arrange
	scenario := "casefold_names"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Malformed tool argument JSON is rejected.
func TestGuardToolCallsMalformedAllowed(t *testing.T) {
	// Arrange
	scenario := "malformed_allowed"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Every call in the response requires approval.
func TestGuardToolCallsFirstCallOnly(t *testing.T) {
	// Arrange
	scenario := "first_call_only"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Log mode still enforces tool authorization.
func TestGuardToolCallsLogBypass(t *testing.T) {
	// Arrange
	scenario := "log_bypass"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// The supplied tool map controls authorization.
func TestGuardToolCallsHardcodedPolicy(t *testing.T) {
	// Arrange
	scenario := "hardcoded_policy"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// URL inspection uses the configured argument key.
func TestGuardToolCallsWrongUrlField(t *testing.T) {
	// Arrange
	scenario := "wrong_url_field"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Streamed tool calls are checked and preserved when allowed.
func TestGuardToolCallsDropStreamTools(t *testing.T) {
	// Arrange
	scenario := "drop_stream_tools"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// One denied streamed call withholds the whole batch.
func TestGuardToolCallsStreamNonAtomic(t *testing.T) {
	// Arrange
	scenario := "stream_non_atomic"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Interleaved tool indices remain independent.
func TestGuardToolCallsMergeIndices(t *testing.T) {
	// Arrange
	scenario := "merge_indices"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Streamed argument fragments are concatenated.
func TestGuardToolCallsLastFragmentOnly(t *testing.T) {
	// Arrange
	scenario := "last_fragment_only"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Assembled tool arguments retain outgoing canary protection.
func TestGuardToolCallsSkipToolCanary(t *testing.T) {
	// Arrange
	scenario := "skip_tool_canary"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// Pending tools do not delay safe content delivery.
func TestGuardToolCallsBufferToolStream(t *testing.T) {
	// Arrange
	scenario := "buffer_tool_stream"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}

// The tool reference preserves all nine earlier stages.
func TestGuardToolCallsAllStages(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testToolScenario(t, scenario, 0, true)
}
func testToolScenario(t *testing.T, scenario string, exitCode int, allStages bool) {
	t.Helper()
	stages := []string{"as4"}
	fixture := scenario
	if allStages {
		stages = append(stages, "ou9", "qe5", "si3", "xd5", "ro3", "wt4", "kg7", "tf0", "fi6")
		fixture = "all_stages"
	}
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		fixture: {StageSlugs: stages, CodePath: "test_helpers/scenarios/base/guard_tool_calls/" + scenario, ExpectedExitCode: exitCode, StdoutFixturePath: "test_helpers/fixtures/base/guard_tool_calls/" + fixture, NormalizeOutputFunc: normalizeStreamOutput},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080: %v", err)
	}
	listener.Close()
}

// Tool stream comparisons reject fragments and the wrong denial rule.
func TestToolStreamRejectsFragments(t *testing.T) {
	// Arrange
	rule := "tool_not_allowed"
	valid := streamResult{rule: rule, errors: 1}
	leaked := valid
	leaked.tools = 1
	wrong := valid
	wrong.rule = "canary_leak"
	// Act
	allowed := checkToolStream(valid, nil, nil, rule)
	fragments := checkToolStream(leaked, nil, nil, rule)
	incorrect := checkToolStream(wrong, nil, nil, rule)
	// Assert
	if allowed != nil || fragments == nil || incorrect == nil {
		t.Fatalf("denial comparison: valid=%v fragments=%v wrong=%v", allowed, fragments, incorrect)
	}
}

// Approved tool comparisons preserve exact IDs, names, and argument strings.
func TestToolStreamPreservesCallValues(t *testing.T) {
	// Arrange
	var call openai.ChatCompletionMessageToolCallUnion
	json.Unmarshal([]byte(`{"id":"call_a","type":"function","function":{"name":"http_get","arguments":"{ \"url\": \"https://allowed.com/\" }"}}`), &call)
	expected := []toolWant{{"call_a", "http_get", `{ "url": "https://allowed.com/" }`}}
	// Act
	valid := checkToolStream(streamResult{}, []openai.ChatCompletionMessageToolCallUnion{call}, expected, "")
	call.Function.Arguments = `{"url":"https://allowed.com/"}`
	changed := checkToolStream(streamResult{}, []openai.ChatCompletionMessageToolCallUnion{call}, expected, "")
	// Assert
	if valid != nil || changed == nil {
		t.Fatalf("argument comparison: valid=%v changed=%v", valid, changed)
	}
}

// Approved call comparisons require the complete ordered batch.
func TestToolStreamRequiresCompleteBatch(t *testing.T) {
	// Arrange
	expected := []toolWant{{"call_a", "get_weather", "{}"}}
	// Act
	missing := checkToolStream(streamResult{}, nil, expected, "")
	// Assert
	if missing == nil {
		t.Fatal("missing call accepted")
	}
}

// Wire parsing counts tool fragments and accepts the expected authorization rule.
func TestToolWireCountsFragmentsAndRule(t *testing.T) {
	// Arrange
	wire := []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a"}]}}]}` + "\n\n" + `data: {"error":{"message":"Blocked","type":"firewall_block","rule":"tool_not_allowed"}}` + "\n\n")
	// Act
	result, err := parseStreamOutput(wire, dlpCanary, "tool_not_allowed")
	// Assert
	if err != nil || result.tools != 1 || result.rule != "tool_not_allowed" || result.errors != 1 {
		t.Fatalf("wire result %+v %v", result, err)
	}
}

// New policies preserve existing DLP settings and use supplied tool rules.
func TestToolPolicyPreservesSettings(t *testing.T) {
	// Arrange
	supplied := `{"fetch":{"url_argument":"target","allowed_hosts":["docs.example.org"]}}`
	// Act
	var actual map[string]json.RawMessage
	err := json.Unmarshal([]byte(toolPolicyJSON("log", supplied)), &actual)
	// Assert
	if err != nil || string(actual["tools"]) != supplied || string(actual["mode"]) != `"log"` || string(actual["dlp"]) != dlpSettingsJSON || !strings.Contains(string(actual["denylist"]), "audit-stream") {
		t.Fatalf("tool policy %v %v", actual, err)
	}
}

// Normalization hides stage-10 addresses while preserving authorization evidence.
func TestToolOutputNormalization(t *testing.T) {
	// Arrange
	input := []byte("--origin http://127.0.0.1:45678 --detector http://127.0.0.1:45679 --policy \"/tmp/firewall-stage-10-123/policy.json\"\nfirst_text_ms=12.3 tool_destination_not_allowed wire_fragments=0 SDK_calls=0\n")
	// Act
	actual := string(normalizeStreamOutput(input))
	// Assert
	if strings.Contains(actual, "45678") || strings.Contains(actual, "stage-10-123") || strings.Contains(actual, "12.3") || !strings.Contains(actual, "tool_destination_not_allowed wire_fragments=0 SDK_calls=0") {
		t.Fatalf("bad normalization %q", actual)
	}
}

// A stream with no tool calls must not inspect serialized empty-batch punctuation.
func TestGuardToolCallsEmptyBatchScan(t *testing.T) {
	// Arrange
	scenario := "scan_empty_batch"
	// Act and Assert
	testToolScenario(t, scenario, 1, false)
}
