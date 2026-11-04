package internal

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"
)

// Request comparison preserves duplicate message multiplicity and original JSON values.
func TestClassifierRequestsAcceptUnorderedMessages(t *testing.T) {
	// Arrange
	first := json.RawMessage(`{"role":"user","content":[{"type":"text","text":"KEEP caf\u00e9"}]}`)
	second := json.RawMessage(`{"role":"assistant","content":null,"tool_calls":[]}`)
	expected := []json.RawMessage{first, second, first}
	requests := []classifierRequest{
		{method: "POST", path: "/classify", contentType: "application/json", body: second},
		{method: "POST", path: "/classify", contentType: "application/json; charset=utf-8", body: []byte(`{"content":[{"text":"KEEP caf\u00e9","type":"text"}],"role":"user"}`)},
		{method: "POST", path: "/classify", contentType: "application/json", body: first},
	}
	// Act
	err := checkClassifierRequests(requests, expected)
	// Assert
	if err != nil {
		t.Fatal(err)
	}
}

// Classifier request validation rejects altered, missing, duplicated, or misrouted messages.
func TestClassifierRequestsRejectWrongTraffic(t *testing.T) {
	// Arrange
	original := json.RawMessage(`{"role":"user","content":"KEEP text"}`)
	clean := classifierRequest{method: "POST", path: "/classify", contentType: "application/json", body: original}
	cases := map[string][]classifierRequest{
		"missing":       nil,
		"duplicate":     {clean, clean},
		"role":          {{method: "POST", path: "/classify", contentType: "application/json", body: []byte(`{"role":"tool","content":"KEEP text"}`)}},
		"text":          {{method: "POST", path: "/classify", contentType: "application/json", body: []byte(`{"role":"user","content":"keep text"}`)}},
		"method":        {{method: "GET", path: "/classify", contentType: "application/json", body: original}},
		"path":          {{method: "POST", path: "/scores", contentType: "application/json", body: original}},
		"content-type":  {{method: "POST", path: "/classify", contentType: "text/plain", body: original}},
		"authorization": {{method: "POST", path: "/classify", contentType: "application/json", authorization: "Bearer dummy", body: original}},
		"json":          {{method: "POST", path: "/classify", contentType: "application/json", body: []byte(`{"role":`)}},
	}
	for name, requests := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			err := checkClassifierRequests(requests, []json.RawMessage{original})
			// Assert
			if err == nil {
				t.Fatal("incorrect classifier traffic passed")
			}
		})
	}
}

// Header validation accepts score categories without pinning exact score totals.
func TestClassifierHeadersAcceptCategories(t *testing.T) {
	// Arrange
	cases := []struct {
		headers  http.Header
		expected classifierExpectation
	}{
		{http.Header{"X-Firewall-Detector-Status": {"ok"}, "X-Firewall-Classifier-Score": {"0"}}, classifierExpectation{threshold: 70}},
		{http.Header{"X-Firewall-Detector-Status": {"ok"}, "X-Firewall-Classifier-Score": {"70"}}, classifierExpectation{threshold: 70, above: true}},
		{http.Header{"X-Firewall-Detector-Status": {"ok"}, "X-Firewall-Classifier-Score": {"100"}}, classifierExpectation{threshold: 85, above: true}},
		{http.Header{"X-Firewall-Detector-Status": {"unavailable"}}, classifierExpectation{unavailable: true}},
	}
	for _, testCase := range cases {
		// Act
		err := checkClassifierHeaders(testCase.headers, testCase.expected)
		// Assert
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Header validation rejects invalid scores and stale scores after a failure.
func TestClassifierHeadersRejectInvalidCategories(t *testing.T) {
	// Arrange
	cases := []struct {
		name, status, score string
		expected            classifierExpectation
	}{
		{"missing-status", "", "20", classifierExpectation{threshold: 70}},
		{"missing-score", "ok", "", classifierExpectation{threshold: 70}},
		{"nonnumeric", "ok", "NaN", classifierExpectation{threshold: 70}},
		{"negative", "ok", "-1", classifierExpectation{threshold: 70}},
		{"too-large", "ok", "101", classifierExpectation{threshold: 70}},
		{"below", "ok", "69", classifierExpectation{threshold: 70, above: true}},
		{"above", "ok", "70", classifierExpectation{threshold: 70}},
		{"stale-after-failure", "unavailable", "92", classifierExpectation{unavailable: true}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			headers := http.Header{"X-Firewall-Detector-Status": {testCase.status}, "X-Firewall-Classifier-Score": {testCase.score}}
			// Act
			err := checkClassifierHeaders(headers, testCase.expected)
			// Assert
			if err == nil {
				t.Fatal("invalid classifier headers passed")
			}
		})
	}
}

// The timeout assertion allows scheduling headroom beyond the learner's 200ms per-call timeout.
func TestClassifierTimeoutAcceptsHeadroom(t *testing.T) {
	// Arrange
	elapsed := 300 * time.Millisecond
	// Act
	err := checkClassifierTimeout(elapsed)
	// Assert
	if err != nil {
		t.Fatal(err)
	}
}

// The timeout assertion rejects the 600ms outer boundary.
func TestClassifierTimeoutRejectsBoundary(t *testing.T) {
	// Arrange
	elapsed := 600 * time.Millisecond
	// Act
	err := checkClassifierTimeout(elapsed)
	// Assert
	if err == nil {
		t.Fatal("unbounded classifier wait passed")
	}
}

// Classifier policies preserve the inherited heuristic table while using supplied settings.
func TestClassifierPolicyPreservesHeuristics(t *testing.T) {
	// Arrange
	var expected map[string]any
	if err := json.Unmarshal([]byte(heuristicPolicyJSON), &expected); err != nil {
		t.Fatal(err)
	}
	expected["mode"] = "log"
	expected["classifier"] = map[string]any{"threshold": float64(85)}
	// Act
	var actual map[string]any
	err := json.Unmarshal([]byte(classifierPolicyJSON("log", 85)), &actual)
	// Assert
	if err != nil || !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected preserved policy plus classifier settings, got %v, err=%v", actual, err)
	}
}
