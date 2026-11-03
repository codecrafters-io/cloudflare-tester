package internal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/codecrafters-io/tester-utils/executable"
	"github.com/codecrafters-io/tester-utils/test_case_harness"
)

func testBindToPort(harness *test_case_harness.TestCaseHarness) error {
	// A pre-existing server must not satisfy a submission's health checks.
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		return fmt.Errorf("tester setup: port 8080 is already in use; stop the other server before retrying")
	}
	listener.Close()

	directory, err := os.MkdirTemp("", "cloudflare-stage-1-")
	if err != nil {
		return err
	}
	policyPath := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(policyPath, []byte("{}\n"), 0644); err != nil {
		os.RemoveAll(directory)
		return err
	}
	harness.Logger.Infof("Wrote %s: {}", policyPath)
	harness.Logger.Infof("$ ./your_program.sh --origin http://127.0.0.1:8081 --detector http://127.0.0.1:8082 --policy %q", policyPath)

	program := harness.Executable
	program.WorkingDir = directory
	program.TimeoutInMilliseconds = 15 * 1000
	if err := program.Start("--origin", "http://127.0.0.1:8081", "--detector", "http://127.0.0.1:8082", "--policy", policyPath); err != nil {
		os.RemoveAll(directory)
		return fmt.Errorf("could not start your program: %w", err)
	}

	// Wait exactly once. The closed channel synchronizes access to the result.
	process := program.Process
	done := make(chan struct{})
	var result executable.ExecutableResult
	var waitError error
	go func() {
		result, waitError = program.Wait()
		close(done)
	}()
	harness.RegisterTeardownFunc(func() {
		defer os.RemoveAll(directory)
		select {
		case <-done:
			return
		default:
		}
		syscall.Kill(-process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			syscall.Kill(-process.Pid, syscall.SIGKILL)
			<-done
		}
	})

	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		harness.Logger.Infof("Sending GET /health to port 8080 (request %d/2)", requestNumber)
		for {
			select {
			case <-done:
				if waitError != nil {
					return fmt.Errorf("your program stopped before completing the health checks: %w", waitError)
				}
				return fmt.Errorf("your program exited with code %d before completing both health checks; keep your HTTP server running", result.ExitCode)
			default:
			}

			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8080/health", nil)
			if err != nil {
				return err
			}
			response, err := client.Do(request)
			if err == nil {
				response.Body.Close()
				if response.StatusCode != http.StatusOK {
					return fmt.Errorf("expected GET /health to return HTTP 200, got HTTP %d", response.StatusCode)
				}
				harness.Logger.Successf("Received HTTP 200 for GET /health")
				break
			}
			if ctx.Err() != nil {
				return fmt.Errorf("no HTTP response from GET /health on port 8080 within 5s; make sure your server keeps running and handles HTTP requests")
			}
			select {
			case <-done:
			case <-ctx.Done():
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return nil
}
