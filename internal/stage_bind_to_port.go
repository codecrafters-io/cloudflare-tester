package internal

import (
	"github.com/codecrafters-io/tester-utils/test_case_harness"
	"time"
)

func testBindToPort(harness *test_case_harness.TestCaseHarness) error {
	process, err := startFirewall(harness, "http://127.0.0.1:8081", "cloudflare-stage-1-", 15*time.Second, "{}\n")
	if err != nil {
		return err
	}
	return checkFirewallHealth(harness, process)
}
