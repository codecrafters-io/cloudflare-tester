package internal

import (
	"bytes"
	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The streaming reference passes stage 9.
func TestInspectStreamsPassAll(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testStreamScenario(t, scenario, 0, false)
}

// The earlier buffered DLP solution cannot inspect split text deltas.
func TestInspectStreamsPreviousStage(t *testing.T) {
	// Arrange
	scenario := "previous_stage"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// Canary prefixes stay withheld until the match can be decided.
func TestInspectStreamsNoHold(t *testing.T) {
	// Arrange
	scenario := "no_hold"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// Canary detection spans event boundaries.
func TestInspectStreamsEventOnly(t *testing.T) {
	// Arrange
	scenario := "event_only"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// Clean completion releases its retained tail.
func TestInspectStreamsMissingTail(t *testing.T) {
	// Arrange
	scenario := "missing_tail"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// A blocked stream discards pending text.
func TestInspectStreamsFlushOnError(t *testing.T) {
	// Arrange
	scenario := "flush_on_error"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// A blocked stream sends exactly one error.
func TestInspectStreamsDuplicateError(t *testing.T) {
	// Arrange
	scenario := "duplicate_error"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// A blocked stream ends without a success terminator.
func TestInspectStreamsDoneAfterError(t *testing.T) {
	// Arrange
	scenario := "done_after_error"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// No content may follow the error event.
func TestInspectStreamsContinueAfterError(t *testing.T) {
	// Arrange
	scenario := "continue_after_error"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// Inspection uses decoded text delta values.
func TestInspectStreamsNoJsonUnescape(t *testing.T) {
	// Arrange
	scenario := "no_json_unescape"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// Streaming uses the policy canary.
func TestInspectStreamsHardcodedCanary(t *testing.T) {
	// Arrange
	scenario := "hardcoded_canary"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// The holdback length counts characters.
func TestInspectStreamsByteHold(t *testing.T) {
	// Arrange
	scenario := "byte_hold"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// Safe content arrives before the origin completes.
func TestInspectStreamsBufferAll(t *testing.T) {
	// Arrange
	scenario := "buffer_all"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// Safe text is flushed to the network incrementally.
func TestInspectStreamsNoFlush(t *testing.T) {
	// Arrange
	scenario := "no_flush"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// The streaming canary is a literal string.
func TestInspectStreamsRegexCanary(t *testing.T) {
	// Arrange
	scenario := "regex_canary"
	// Act and Assert
	testStreamScenario(t, scenario, 1, false)
}

// The streaming reference preserves all eight earlier stages.
func TestInspectStreamsAllStages(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testStreamScenario(t, scenario, 0, true)
}
func testStreamScenario(t *testing.T, scenario string, exitCode int, allStages bool) {
	t.Helper()
	stages := []string{"ou9"}
	fixture := scenario
	if allStages {
		stages = append(stages, "qe5", "si3", "xd5", "ro3", "wt4", "kg7", "tf0", "fi6")
		fixture = "all_stages"
	}
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		fixture: {StageSlugs: stages, CodePath: "test_helpers/scenarios/base/inspect_streams/" + scenario, ExpectedExitCode: exitCode, StdoutFixturePath: "test_helpers/fixtures/base/inspect_streams/" + fixture, NormalizeOutputFunc: normalizeStreamOutput},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080 after teardown: %v", err)
	}
	listener.Close()
}

var streamMeasurement = regexp.MustCompile(`first_text_ms=[0-9]+\.[0-9]+`)

func normalizeStreamOutput(output []byte) []byte {
	output = streamMeasurement.ReplaceAll(output, []byte("first_text_ms=<measured>"))
	return normalizeClassifierOutput(output)
}

// Clean stream comparison accepts different event chunking and preserves Unicode.
func TestStreamParserRechunksText(t *testing.T) {
	// Arrange
	wire := []byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\r\n\r\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"caf\\u00e9 \"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
	// Act
	result, err := parseStreamOutput(wire, "marker")
	// Assert
	if err != nil || result.text != "caf\u00e9 ok" || result.errors != 0 || result.done != 1 {
		t.Fatalf("unexpected result %+v %v", result, err)
	}
}

// Stream parsing rejects extra terminal events even when the SDK stops at the first.
func TestStreamParserRejectsExtraEvents(t *testing.T) {
	// Arrange
	errorEvent := `data: {"error":{"message":"Blocked","type":"firewall_block","rule":"canary_leak"}}` + "\n\n"
	for _, wire := range []string{errorEvent + errorEvent, errorEvent + "data: [DONE]\n\n", "data: [DONE]\n\ndata: {}\n\n"} {
		// Act
		_, err := parseStreamOutput([]byte(wire), "marker")
		// Assert
		if err == nil {
			t.Fatalf("extra events were accepted: %q", wire)
		}
	}
}

// Stream parsing requires valid JSON, complete frames, and a named safe error.
func TestStreamParserRejectsMalformedData(t *testing.T) {
	// Arrange
	inputs := []string{"data: {} {}\n\n", "data: {}\n", `data: {"error":{"message":"marker","type":"firewall_block","rule":"canary_leak"}}` + "\n\n", `data: {"error":{"message":"Blocked","type":"wrong","rule":"canary_leak"}}` + "\n\n", "data: {\"choices\":[{\"index\":1,\"delta\":{}}]}\n\n", string([]byte{'d', 'a', 't', 'a', ':', ' ', 0xff, '\n', '\n'})}
	for _, wire := range inputs {
		// Act
		_, err := parseStreamOutput([]byte(wire), "marker")
		// Assert
		if err == nil {
			t.Fatalf("malformed event was accepted: %q", wire)
		}
	}
}

// A blocked stream cannot release even a partial marker.
func TestStreamVerdictRejectsPartialLeak(t *testing.T) {
	// Arrange
	testCase := streamCase{blocked: true, safePrefix: "safe text "}
	allowed := streamResult{text: "safe ", errors: 1}
	leaked := streamResult{text: "safe text CA", errors: 1}
	// Act
	cleanError := checkStreamResult(allowed, testCase)
	leakError := checkStreamResult(leaked, testCase)
	// Assert
	if cleanError != nil || leakError == nil {
		t.Fatalf("prefix check: clean=%v leaked=%v", cleanError, leakError)
	}
}

// Clean streams must retain their full text and success terminator.
func TestStreamVerdictRequiresCompleteText(t *testing.T) {
	// Arrange
	testCase := streamCase{want: "complete"}
	// Act
	valid := checkStreamResult(streamResult{text: "complete", done: 1}, testCase)
	missingTail := checkStreamResult(streamResult{text: "comp", done: 1}, testCase)
	missingDone := checkStreamResult(streamResult{text: "complete"}, testCase)
	// Assert
	if valid != nil || missingTail == nil || missingDone == nil {
		t.Fatalf("clean check: valid=%v tail=%v done=%v", valid, missingTail, missingDone)
	}
}

// First content must arrive strictly before the one-second limit.
func TestStreamLatencyBoundary(t *testing.T) {
	// Arrange
	before := 999 * time.Millisecond
	boundary := time.Second
	// Act
	allowed := checkStreamLatency(before)
	late := checkStreamLatency(boundary)
	absent := checkStreamLatency(-1)
	// Assert
	if allowed != nil || late == nil || absent == nil {
		t.Fatalf("timing check: before=%v boundary=%v absent=%v", allowed, late, absent)
	}
}

// Normalization hides measured times and addresses while preserving the timing limit.
func TestStreamOutputNormalization(t *testing.T) {
	// Arrange
	input := []byte("--origin http://127.0.0.1:45678 --detector http://127.0.0.1:45679 --policy \"/tmp/firewall-stage-9-123/policy.json\"\nfirst_text_ms=12.3 limit_ms=1000.0 origin_delay_ms=2000 errors=1 done=0 canary_leak\n")
	// Act
	actual := normalizeStreamOutput(input)
	// Assert
	if bytes.Contains(actual, []byte("45678")) || bytes.Contains(actual, []byte("stage-9-123")) || bytes.Contains(actual, []byte("12.3")) || !strings.Contains(string(actual), "limit_ms=1000.0 origin_delay_ms=2000 errors=1 done=0 canary_leak") {
		t.Fatalf("normalization changed evidence: %q", actual)
	}
}
