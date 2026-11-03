package internal

import (
	"encoding/json"
	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
	"net"
	"strings"
	"testing"
)

// DLP reference passes stage 8.
func TestStopDataLeaksPassAll(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testDLPScenario(t, scenario, 0, false)
}

// Earlier implementation fails because origin content is not redacted.
func TestStopDataLeaksPreviousStage(t *testing.T) {
	// Arrange
	scenario := "previous_stage"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Redaction is required before forwarding.
func TestStopDataLeaksSkipRedaction(t *testing.T) {
	// Arrange
	scenario := "skip_redaction"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Repeated exact values reuse a placeholder.
func TestStopDataLeaksReuseValues(t *testing.T) {
	// Arrange
	scenario := "reuse_values"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Placeholder mappings span message boundaries.
func TestStopDataLeaksPerMessageMap(t *testing.T) {
	// Arrange
	scenario := "per_message_map"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Redaction includes system and assistant content.
func TestStopDataLeaksUsersOnly(t *testing.T) {
	// Arrange
	scenario := "users_only"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Redaction includes text parts.
func TestStopDataLeaksStringsOnly(t *testing.T) {
	// Arrange
	scenario := "strings_only"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Redaction uses the supplied regex patterns.
func TestStopDataLeaksHardcodedPatterns(t *testing.T) {
	// Arrange
	scenario := "hardcoded_patterns"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Policy order breaks equal-start match ties.
func TestStopDataLeaksWrongOverlapOrder(t *testing.T) {
	// Arrange
	scenario := "wrong_overlap_order"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Outgoing canaries are blocked.
func TestStopDataLeaksSkipOutput(t *testing.T) {
	// Arrange
	scenario := "skip_output"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// JSON escapes cannot conceal a canary.
func TestStopDataLeaksRawOnlyCanary(t *testing.T) {
	// Arrange
	scenario := "raw_only_canary"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Every completion choice is inspected.
func TestStopDataLeaksFirstChoiceOnly(t *testing.T) {
	// Arrange
	scenario := "first_choice_only"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Outgoing matching uses the supplied canary.
func TestStopDataLeaksHardcodedCanary(t *testing.T) {
	// Arrange
	scenario := "hardcoded_canary"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// Log mode still blocks outgoing canaries.
func TestStopDataLeaksLogAllowsCanary(t *testing.T) {
	// Arrange
	scenario := "log_allows_canary"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}

// The DLP reference preserves all seven earlier stages.
func TestStopDataLeaksAllStages(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testDLPScenario(t, scenario, 0, true)
}

func testDLPScenario(t *testing.T, scenario string, exitCode int, allStages bool) {
	t.Helper()
	stages := []string{"qe5"}
	fixture := scenario
	if allStages {
		stages = append(stages, "si3", "xd5", "ro3", "wt4", "kg7", "tf0", "fi6")
		fixture = "all_stages"
	}
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		fixture: {StageSlugs: stages, CodePath: "test_helpers/scenarios/base/stop_data_leaks/" + scenario, ExpectedExitCode: exitCode, StdoutFixturePath: "test_helpers/fixtures/base/stop_data_leaks/" + fixture, NormalizeOutputFunc: normalizeClassifierOutput},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("firewall still owns port 8080 after teardown: %v", err)
	}
	listener.Close()
}

// Semantic comparison preserves exact large numbers instead of rounding them.
func TestDLPRequestRetainsNumbers(t *testing.T) {
	// Arrange
	original := []byte(`{"n":9007199254740993,"messages":[]}`)
	request := originRequest{method: "POST", path: "/v1/chat/completions", host: "origin", authorization: "Bearer course-test-key", contentType: "application/json", body: original}
	// Act
	err := checkDLPRequest(request, original, string(original), "origin")
	request.body = []byte(`{"messages":[],"n":9007199254740992}`)
	rounded := checkDLPRequest(request, original, string(original), "origin")
	// Assert
	if err != nil || rounded == nil {
		t.Fatalf("exact numbers: valid=%v rounded=%v", err, rounded)
	}
}

// Semantic comparison rejects extra fields and trailing JSON after redaction.
func TestDLPRequestRejectsExtraData(t *testing.T) {
	// Arrange
	expected := `{"messages":[]}`
	request := originRequest{method: "POST", path: "/v1/chat/completions", host: "origin", authorization: "Bearer course-test-key", contentType: "application/json"}
	for _, body := range []string{`{"messages":[],"extra":true}`, `{"messages":[]} {}`, `{"messages":[]}`} {
		request.body = []byte(body)
		// Act
		err := checkDLPRequest(request, []byte(expected), expected, "origin")
		// Assert
		if (err == nil) != (body == expected) {
			t.Fatalf("body %q error %v", body, err)
		}
	}
}

// DLP policy construction preserves earlier decisions and uses supplied data.
func TestDLPPolicyPreservesSettings(t *testing.T) {
	// Arrange
	base := decisionPolicyJSON("log", "fail_closed", decisionThresholdsJSON)
	// Act
	actual := dlpPolicyJSON(base, dlpSettingsJSON)
	var policy map[string]json.RawMessage
	err := json.Unmarshal([]byte(actual), &policy)
	// Assert
	if err != nil || string(policy["dlp"]) != dlpSettingsJSON {
		t.Fatalf("DLP settings missing: %s %v", actual, err)
	}
	delete(policy, "dlp")
	remaining, _ := json.Marshal(policy)
	var expected map[string]json.RawMessage
	json.Unmarshal([]byte(base), &expected)
	normalized, _ := json.Marshal(expected)
	if string(remaining) != string(normalized) {
		t.Fatalf("earlier settings changed: %s", remaining)
	}
}

// Address normalization retains the canary, placeholders, and output verdict.
func TestDLPOutputNormalization(t *testing.T) {
	// Arrange
	input := `--origin http://127.0.0.1:45678 --detector http://127.0.0.1:45679 --policy "/tmp/cloudflare-stage-8-123/policy.json"
HTTP 403 canary_leak CANARY_COURSE_7F2A [REDACTED_2]
`
	// Act
	actual := string(normalizeClassifierOutput([]byte(input)))
	// Assert
	if strings.Contains(actual, "45678") || strings.Contains(actual, "stage-8-123") || !strings.Contains(actual, "HTTP 403 canary_leak CANARY_COURSE_7F2A [REDACTED_2]") {
		t.Fatalf("unexpected normalization %q", actual)
	}
}

// Requests without redactions preserve their byte formatting.
func TestDLPRequestKeepsOriginalBytes(t *testing.T) {
	// Arrange
	original := []byte(`{ "messages": [] }`)
	request := originRequest{method: "POST", path: "/v1/chat/completions", host: "origin", authorization: "Bearer course-test-key", contentType: "application/json", body: original}
	// Act
	unchanged := checkDLPRequest(request, original, "", "origin")
	request.body = []byte(`{"messages":[]}`)
	reformatted := checkDLPRequest(request, original, "", "origin")
	// Assert
	if unchanged != nil || reformatted == nil {
		t.Fatalf("byte preservation: unchanged=%v reformatted=%v", unchanged, reformatted)
	}
}

// Redaction does not change origin routing or authentication.
func TestDLPRequestPreservesRouting(t *testing.T) {
	// Arrange
	expected := `{"messages":[]}`
	original := originRequest{method: "POST", path: "/v1/chat/completions", host: "origin", authorization: "Bearer course-test-key", contentType: "application/json", body: []byte(expected)}
	for _, field := range []string{"method", "path", "host", "authorization", "content-type"} {
		request := original
		switch field {
		case "method":
			request.method = "GET"
		case "path":
			request.path = "/wrong"
		case "host":
			request.host = "wrong"
		case "authorization":
			request.authorization = ""
		case "content-type":
			request.contentType = "text/plain"
		}
		// Act
		err := checkDLPRequest(request, []byte(expected), expected, "origin")
		// Assert
		if err == nil {
			t.Fatalf("lost %s was accepted", field)
		}
	}
}

// A denial must not hide the leaked marker in an escaped extra JSON field.
func TestStopDataLeaksEscapedDenialLeak(t *testing.T) {
	// Arrange
	scenario := "leak_extra_field"
	// Act and Assert
	testDLPScenario(t, scenario, 1, false)
}
