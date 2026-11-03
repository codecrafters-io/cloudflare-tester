package internal

import (
	"encoding/base64"
	"encoding/json"
	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
	"net"
	"strings"
	"testing"
)

// The export reference passes the synthetic finale and replay.
func TestStopExfiltrationPassAll(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testExportScenario(t, scenario, 0, false)
}

// The earlier tool guard permits private exports to allowed browsing hosts.
func TestStopExfiltrationPreviousStage(t *testing.T) {
	// Arrange
	scenario := "previous_stage"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Private exports require explicit authorization.
func TestStopExfiltrationSkipExports(t *testing.T) {
	// Arrange
	scenario := "skip_exports"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Tool result names do not establish the producing tool.
func TestStopExfiltrationTrustResultName(t *testing.T) {
	// Arrange
	scenario := "trust_result_name"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Each private field is protected independently.
func TestStopExfiltrationWholeRecordOnly(t *testing.T) {
	// Arrange
	scenario := "whole_record_only"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Normalized and encoded private values remain protected.
func TestStopExfiltrationLiteralOnly(t *testing.T) {
	// Arrange
	scenario := "literal_only"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Base64 query values are inspected after URL parsing.
func TestStopExfiltrationSkipQueryValues(t *testing.T) {
	// Arrange
	scenario := "skip_query_values"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Approved email domains match exactly.
func TestStopExfiltrationSubstringDomain(t *testing.T) {
	// Arrange
	scenario := "substring_domain"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// The export permission includes the tool name.
func TestStopExfiltrationDestinationOnly(t *testing.T) {
	// Arrange
	scenario := "destination_only"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Every outgoing call must pass export authorization.
func TestStopExfiltrationFirstCallOnly(t *testing.T) {
	// Arrange
	scenario := "first_call_only"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Public results remain usable at unapproved destinations.
func TestStopExfiltrationAllResultsPrivate(t *testing.T) {
	// Arrange
	scenario := "all_results_private"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Private values do not carry into a new request.
func TestStopExfiltrationPersistentState(t *testing.T) {
	// Arrange
	scenario := "persistent_state"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Export permissions come from the supplied policy.
func TestStopExfiltrationHardcodedExports(t *testing.T) {
	// Arrange
	scenario := "hardcoded_exports"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Streamed private exports are denied before any tool fragment is emitted.
func TestStopExfiltrationSkipStream(t *testing.T) {
	// Arrange
	scenario := "skip_stream"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Non-streaming responses enforce the same private export rule.
func TestStopExfiltrationSkipNonstream(t *testing.T) {
	// Arrange
	scenario := "skip_nonstream"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// The final reference preserves all ten earlier stages.
func TestStopExfiltrationAllStages(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testExportScenario(t, scenario, 0, true)
}
func testExportScenario(t *testing.T, scenario string, exitCode int, allStages bool) {
	t.Helper()
	stages := []string{"mu9"}
	fixture := scenario
	if allStages {
		stages = append(stages, "as4", "ou9", "qe5", "si3", "xd5", "ro3", "wt4", "kg7", "tf0", "fi6")
		fixture = "all_stages"
	}
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		fixture: {StageSlugs: stages, CodePath: "test_helpers/scenarios/base/stop_exfiltration/" + scenario, ExpectedExitCode: exitCode, StdoutFixturePath: "test_helpers/fixtures/base/stop_exfiltration/" + fixture, NormalizeOutputFunc: normalizeStreamOutput},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080: %v", err)
	}
	listener.Close()
}

// Scoreboard counts observed outcomes rather than the expected labels.
func TestExportScoreboardCountsOutcomes(t *testing.T) {
	// Arrange
	var scoreboard courseScoreboard
	// Act
	scoreboard.observe(true, true)
	scoreboard.observe(true, false)
	scoreboard.observe(false, true)
	scoreboard.observe(false, false)
	// Assert
	if scoreboard.attacks != 2 || scoreboard.blockedAttacks != 1 || scoreboard.benign != 2 || scoreboard.blockedBenign != 1 {
		t.Fatalf("incorrect counts: %+v", scoreboard)
	}
}

// The scoreboard identifies the limited synthetic course suite.
func TestExportScoreboardLabelsScope(t *testing.T) {
	// Arrange
	scoreboard := courseScoreboard{25, 25, 15, 0}
	// Act
	actual := scoreboard.String()
	// Assert
	if actual != "Course test suite (synthetic): 25/25 attacks blocked; 0/15 benign conversations blocked" {
		t.Fatalf("misleading scoreboard %q", actual)
	}
}

// Private record fields are independently long enough for bounded matching.
func TestExportFixturePrivateFields(t *testing.T) {
	// Arrange
	var fields map[string]string
	json.Unmarshal([]byte(privateRecord), &fields)
	// Act and Assert
	if len(fields) != 3 {
		t.Fatal("expected three named private strings")
	}
	for name, value := range fields {
		if len([]rune(value)) < 8 {
			t.Fatalf("short private field %s", name)
		}
	}
	if fields["email"] != "mira.chen@example.net" || fields["customer_id"] != "Customer-4829" {
		t.Fatal("worked example changed")
	}
}

// The encoded record matches an independently generated Python base64 value.
func TestExportFixtureBase64(t *testing.T) {
	// Arrange
	expected := "eyJjdXN0b21lcl9pZCI6IkN1c3RvbWVyLTQ4MjkiLCJlbWFpbCI6Im1pcmEuY2hlbkBleGFtcGxlLm5ldCIsIm5vdGVzIjoiUmVuZXdhbCBwbGFuIE1heSJ9"
	// Act
	actual := base64.StdEncoding.EncodeToString([]byte(privateRecord))
	// Assert
	if actual != expected {
		t.Fatalf("base64 record changed: %s", actual)
	}
}

// History distinguishes producing call IDs from misleading result names.
func TestExportFixtureProvenance(t *testing.T) {
	// Arrange
	raw := exportHistory("read_customer_record", privateRecord, "Public-directory-entry")
	var request struct {
		Messages []struct {
			Role, Name, Content string
			ToolCallID          string `json:"tool_call_id"`
			ToolCalls           []struct {
				ID       string
				Function struct{ Name string }
			} `json:"tool_calls"`
		}
	}
	// Act
	err := json.Unmarshal([]byte(raw), &request)
	// Assert
	if err != nil || len(request.Messages) != 5 {
		t.Fatalf("bad history %s", raw)
	}
	calls := request.Messages[2].ToolCalls
	if calls[0].ID != "call_email" || calls[1].ID != "call_3" || calls[1].Function.Name != "read_customer_record" || request.Messages[3].ToolCallID != "call_3" || request.Messages[3].Name != "read_email" || request.Messages[4].Name != "read_customer_record" {
		t.Fatalf("provenance controls lost: %s", raw)
	}
}

// Export policy preserves detectors while deliberately leaving fixture values visible.
func TestExportFixturePolicy(t *testing.T) {
	// Arrange
	var actual map[string]json.RawMessage
	// Act
	err := json.Unmarshal([]byte(exportPolicyJSON("log", exportSettingsJSON)), &actual)
	// Assert
	if err != nil || string(actual["exports"]) != exportSettingsJSON || string(actual["tools"]) != exportToolsJSON || string(actual["mode"]) != `"log"` || !strings.Contains(string(actual["dlp"]), `"patterns":[]`) || actual["normalization"] == nil || actual["decisions"] == nil || actual["classifier"] == nil {
		t.Fatalf("policy settings lost: %v %v", actual, err)
	}
}

// Output normalization removes only allocated addresses and timing measurements.
func TestExportOutputNormalization(t *testing.T) {
	// Arrange
	input := []byte("--origin http://127.0.0.1:45678 --detector http://127.0.0.1:45679 --policy \"/tmp/cloudflare-stage-11-123/policy.json\"\nfirst_text_ms=12.3 private_export call_3 classifier 12\n")
	// Act
	actual := string(normalizeStreamOutput(input))
	// Assert
	if strings.Contains(actual, "45678") || strings.Contains(actual, "stage-11-123") || strings.Contains(actual, "12.3") || !strings.Contains(actual, "private_export call_3 classifier 12") {
		t.Fatalf("bad normalization %q", actual)
	}
}

// A private denial withholds approved calls earlier in the streamed batch.
func TestStopExfiltrationStreamNonAtomic(t *testing.T) {
	// Arrange
	scenario := "stream_non_atomic"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// Error inspection rejects JSON-escaped private values without suppressing clean diagnostics.
func TestExportErrorKeepsValuesPrivate(t *testing.T) {
	// Arrange
	secret := []string{"mira.chen@example.net"}
	clean := []byte(`{"error":{"message":"Private export denied","rule":"private_export"}}`)
	leaked := []byte(`{"error":{"message":"Blocked mira.chen@example.net"}}`)
	escaped := []byte(`{"error":{"message":"Blocked \u006dira.chen@example.net"}}`)
	// Act
	good := checkPrivateError(clean, secret)
	bad := checkPrivateError(leaked, secret)
	encoded := checkPrivateError(escaped, secret)
	// Assert
	if good != nil || bad == nil || encoded == nil {
		t.Fatalf("error disclosure comparison: clean=%v raw=%v escaped=%v", good, bad, encoded)
	}
}

// A non-streaming denial never echoes private data.
func TestStopExfiltrationLeakNonstreamError(t *testing.T) {
	// Arrange
	scenario := "leak_nonstream_error"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}

// A streamed error never echoes private data.
func TestStopExfiltrationLeakStreamError(t *testing.T) {
	// Arrange
	scenario := "leak_stream_error"
	// Act and Assert
	testExportScenario(t, scenario, 1, false)
}
