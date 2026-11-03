package internal

import (
	"time"

	"github.com/codecrafters-io/tester-utils/tester_definition"
)

var testerDefinition = tester_definition.TesterDefinition{
	ExecutableFileName: "your_program.sh",
	TestCases: []tester_definition.TestCase{
		{Slug: "fi6", TestFunc: testBindToPort, Timeout: 20 * time.Second},
		{Slug: "tf0", TestFunc: testProxyAPI, Timeout: 30 * time.Second},
		{Slug: "kg7", TestFunc: testBlockAndLog, Timeout: 45 * time.Second},
		{Slug: "wt4", TestFunc: testDefeatEvasion, Timeout: 45 * time.Second},
		{Slug: "ro3", TestFunc: testScoreWithHeuristics, Timeout: 45 * time.Second},
		{Slug: "xd5", TestFunc: testCallClassifier, Timeout: 60 * time.Second},
		{Slug: "si3", TestFunc: testDecideWithThresholds, Timeout: 60 * time.Second},
		{Slug: "qe5", TestFunc: testStopDataLeaks, Timeout: 60 * time.Second},
		{Slug: "ou9", TestFunc: testInspectStreams, Timeout: 60 * time.Second},
		{Slug: "as4", TestFunc: testGuardToolCalls, Timeout: 60 * time.Second},
		{Slug: "mu9", TestFunc: testStopExfiltration, Timeout: 60 * time.Second},
	},
}
