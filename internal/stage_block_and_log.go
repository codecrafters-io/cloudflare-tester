package internal

import (
	"fmt"
	"github.com/codecrafters-io/tester-utils/test_case_harness"
)

func testBlockAndLog(harness *test_case_harness.TestCaseHarness) error {
	harness.Logger.Infof("Block and log: this stage is not implemented yet")
	return fmt.Errorf("this stage is not implemented yet")
}
