package internal

import (
	"time"

	"github.com/codecrafters-io/tester-utils/tester_definition"
)

var testerDefinition = tester_definition.TesterDefinition{
	ExecutableFileName: "your_program.sh",
	TestCases: []tester_definition.TestCase{
		{Slug: "fi6", TestFunc: testBindToPort, Timeout: 20 * time.Second},
		{Slug: "tf0", TestFunc: testProxyAPI},
		{Slug: "kg7", TestFunc: testBlockAndLog},
		{Slug: "wt4", TestFunc: testDefeatEvasion},
		{Slug: "ro3", TestFunc: testScoreWithHeuristics},
		{Slug: "xd5", TestFunc: testCallClassifier},
		{Slug: "si3", TestFunc: testDecideWithThresholds},
		{Slug: "qe5", TestFunc: testStopDataLeaks},
		{Slug: "ou9", TestFunc: testInspectStreams},
		{Slug: "as4", TestFunc: testGuardToolCalls},
		{Slug: "mu9", TestFunc: testStopExfiltration},
	},
}
