package internal

import (
	"net"
	"net/http"
	"regexp"
	"testing"

	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
)

// A server that keeps answering health checks passes the stage.
func TestBindToPortSuccess(t *testing.T) {
	// Arrange
	scenario := "pass_all"
	// Act and Assert
	testStage1Scenario(t, scenario, 0)
}

// A server may take a short time to start listening.
func TestBindToPortDelayedStart(t *testing.T) {
	// Arrange
	scenario := "delayed_start"
	// Act and Assert
	testStage1Scenario(t, scenario, 0)
}

// Responses within the documented five-second budget are accepted.
func TestBindToPortSlowResponse(t *testing.T) {
	// Arrange
	scenario := "slow_response"
	// Act and Assert
	testStage1Scenario(t, scenario, 0)
}

// A server already on port 8080 cannot satisfy a learner's health checks.
func TestBindToPortOccupiedPort(t *testing.T) {
	// Arrange
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	done := make(chan struct{})
	go func() {
		server.Serve(listener)
		close(done)
	}()
	defer func() {
		server.Close()
		listener.Close()
		<-done
	}()

	// Act and Assert
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		"occupied_port": {
			StageSlugs:          []string{"fi6"},
			CodePath:            "test_helpers/scenarios/base/exit_early",
			ExpectedExitCode:    1,
			StdoutFixturePath:   "test_helpers/fixtures/base/occupied_port",
			NormalizeOutputFunc: normalizeStage1Output,
		},
	})
}

// A response body is permitted because only the status code matters.
func TestBindToPortResponseBody(t *testing.T) {
	// Arrange
	scenario := "response_body"
	// Act and Assert
	testStage1Scenario(t, scenario, 0)
}

// An early exit reports the learner's exit code.
func TestBindToPortEarlyExit(t *testing.T) {
	// Arrange
	scenario := "exit_early"
	// Act and Assert
	testStage1Scenario(t, scenario, 1)
}

// An HTTP error status fails the health check.
func TestBindToPortWrongStatus(t *testing.T) {
	// Arrange
	scenario := "wrong_status"
	// Act and Assert
	testStage1Scenario(t, scenario, 1)
}

// Redirecting to a healthy route cannot satisfy the health check.
func TestBindToPortRedirect(t *testing.T) {
	// Arrange
	scenario := "redirect"
	// Act and Assert
	testStage1Scenario(t, scenario, 1)
}

// A process that never listens fails within the startup deadline.
func TestBindToPortNeverListens(t *testing.T) {
	// Arrange
	scenario := "never_listens"
	// Act and Assert
	testStage1Scenario(t, scenario, 1)
}

// A connection that never returns HTTP headers cannot hang the tester.
func TestBindToPortNeverResponds(t *testing.T) {
	// Arrange
	scenario := "never_responds"
	// Act and Assert
	testStage1Scenario(t, scenario, 1)
}

// A server that exits after its first request cannot pass the stage.
func TestBindToPortOneRequest(t *testing.T) {
	// Arrange
	scenario := "one_request"
	// Act and Assert
	testStage1Scenario(t, scenario, 1)
}

func testStage1Scenario(t *testing.T, scenario string, exitCode int) {
	t.Helper()
	tester_utils_testing.TestTesterOutput(t, testerDefinition, map[string]tester_utils_testing.TesterOutputTestCase{
		scenario: {
			StageSlugs:          []string{"fi6"},
			CodePath:            "test_helpers/scenarios/base/" + scenario,
			ExpectedExitCode:    exitCode,
			StdoutFixturePath:   "test_helpers/fixtures/base/" + scenario,
			NormalizeOutputFunc: normalizeStage1Output,
		},
	})
	// Process teardown must release the port on both success and failure.
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("learner server still owns port 8080 after teardown: %v", err)
	}
	listener.Close()
}

var stage1PolicyPath = regexp.MustCompile(`/[^\s"]*/cloudflare-stage-1-[^/\s"]+/policy\.json`)

func normalizeStage1Output(output []byte) []byte {
	return stage1PolicyPath.ReplaceAll(output, []byte("<temporary-directory>/policy.json"))
}
