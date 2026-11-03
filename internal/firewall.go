package internal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/codecrafters-io/tester-utils/executable"
	"github.com/codecrafters-io/tester-utils/test_case_harness"
)

type firewallProcess struct {
	done      chan struct{}
	result    executable.ExecutableResult
	waitError error
	stop      func()
}

func startFirewall(harness *test_case_harness.TestCaseHarness, origin, directoryPrefix string, timeout time.Duration, policy string) (*firewallProcess, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		return nil, fmt.Errorf("tester setup: port 8080 is already in use; stop the other server before retrying")
	}
	listener.Close()
	// On macOS, the loopback bind succeeds even while a server listens on all interfaces.
	if connection, err := net.DialTimeout("tcp", "127.0.0.1:8080", time.Second); err == nil {
		connection.Close()
		return nil, fmt.Errorf("tester setup: port 8080 is already in use; stop the other server before retrying")
	}
	directory, err := os.MkdirTemp("", directoryPrefix)
	if err != nil {
		return nil, err
	}
	policyPath := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(policyPath, []byte(policy), 0644); err != nil {
		os.RemoveAll(directory)
		return nil, err
	}
	harness.Logger.Infof("Wrote %s: %s", policyPath, strings.TrimSpace(policy))
	harness.Logger.Infof("$ ./your_program.sh --origin %s --detector http://127.0.0.1:8082 --policy %q", origin, policyPath)
	program := harness.Executable
	program.WorkingDir = directory
	program.TimeoutInMilliseconds = int(timeout / time.Millisecond)
	if err := program.Start("--origin", origin, "--detector", "http://127.0.0.1:8082", "--policy", policyPath); err != nil {
		os.RemoveAll(directory)
		return nil, fmt.Errorf("could not start your program: %w", err)
	}
	process := program.Process
	state := &firewallProcess{done: make(chan struct{})}
	go func() {
		state.result, state.waitError = program.Wait()
		close(state.done)
	}()
	state.stop = func() {
		defer os.RemoveAll(directory)
		select {
		case <-state.done:
			return
		default:
		}
		syscall.Kill(-process.Pid, syscall.SIGTERM)
		select {
		case <-state.done:
		case <-time.After(2 * time.Second):
			syscall.Kill(-process.Pid, syscall.SIGKILL)
			<-state.done
		}
	}
	harness.RegisterTeardownFunc(state.stop)
	return state, nil
}

func firewallHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func checkFirewallHealth(harness *test_case_harness.TestCaseHarness, process *firewallProcess) error {
	client := firewallHTTPClient(5 * time.Second)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		harness.Logger.Infof("Sending GET /health to port 8080 (request %d/2)", requestNumber)
		for {
			select {
			case <-process.done:
				if process.waitError != nil {
					return fmt.Errorf("your program stopped before completing the health checks: %w", process.waitError)
				}
				return fmt.Errorf("your program exited with code %d before completing both health checks; keep your HTTP server running", process.result.ExitCode)
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
			case <-process.done:
			case <-ctx.Done():
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return nil
}
