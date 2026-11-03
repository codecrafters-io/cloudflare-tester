package internal

import (
	"github.com/codecrafters-io/tester-utils/test_case_harness"
	"time"
)

func runToolStreamCases(h *test_case_harness.TestCaseHarness) error {
	fragment := func(index int, id, name, arguments string) streamPart {
		return streamPart{raw: toolDelta("", toolFragment(index, id, name, arguments))}
	}
	safe := "safe introduction printed before private content. "
	if err := runStreamCases(h, "log", dlpCanary, []streamCase{
		{name: "streamed-host-grows-into-bypass", parts: []streamPart{fragment(0, "call_url", "http_", `{"url":"https://allowed.com`), fragment(0, "", "get", `.evil.io/"}`)}, blocked: true, toolRule: "tool_destination_not_allowed"},
		{name: "preserve-fragmented-approved-call", parts: []streamPart{fragment(0, "call_page", "http_", `{ "url": "https://allowed.`), fragment(0, "", "get", `com/", "retain":9007199254740993 }`)}, toolCalls: []toolWant{{"call_page", "http_get", `{ "url": "https://allowed.com/", "retain":9007199254740993 }`}}},
		{name: "interleaved-tool-indices", parts: []streamPart{fragment(1, "call_page", "http_", `{"url":"https://allowed.`), fragment(0, "call_weather", "get_", `{"city":"Pa`), fragment(1, "", "get", `com/"}`), fragment(0, "", "weather", `ris"}`)}, toolCalls: []toolWant{{"call_weather", "get_weather", `{"city":"Paris"}`}, {"call_page", "http_get", `{"url":"https://allowed.com/"}`}}},
		{name: "bad-later-call-withholds-allowed-call", parts: []streamPart{fragment(0, "call_safe", "get_weather", `{"city":"Paris"}`), fragment(1, "call_bad", "run_shell", `{}`)}, blocked: true, toolRule: "tool_not_allowed"},
		{name: "reject-incomplete-streamed-arguments", parts: []streamPart{fragment(0, "call_url", "http_get", `{"url":"https://allowed.com/`)}, blocked: true, toolRule: "tool_arguments_invalid"},
		{name: "valid-json-prefix-is-not-completion", parts: []streamPart{fragment(0, "call_url", "http_get", `{"url":"https://allowed.com/"}`), fragment(0, "", "", ` trailing`)}, blocked: true, toolRule: "tool_arguments_invalid"},
		{name: "complete-name-before-authorization", parts: []streamPart{fragment(0, "call_tool", "get_weather", `{}`), fragment(0, "", "_shell", ``)}, blocked: true, toolRule: "tool_not_allowed"},
		{name: "assembled-tool-arguments-canary", parts: []streamPart{fragment(0, "call_url", "http_get", `{"url":"https://allowed.com/?q=CANARY_`), fragment(0, "", "", `COURSE_7F2A"}`)}, blocked: true, toolRule: "canary_leak"},
		{name: "text-canary-discards-buffered-tools", parts: []streamPart{fragment(0, "call_safe", "get_weather", `{}`), {text: "CA"}, {text: "NARY_"}, {text: "COUR"}, {text: "SE_7"}, {text: "F2A"}}, blocked: true, toolRule: "canary_leak"},
		{name: "text-still-streams-with-pending-tools", parts: []streamPart{{raw: toolDelta(safe, toolFragment(0, "call_url", "http_get", `{"url":"https://allowed.`))}, {raw: toolDelta("", toolFragment(0, "", "", `com/"}`)), delay: 2 * time.Second}}, want: safe, latency: true, toolCalls: []toolWant{{"call_url", "http_get", `{"url":"https://allowed.com/"}`}}},
	}, toolPolicyJSON("log", toolsJSON)); err != nil {
		return err
	}
	return runStreamCases(h, "block", "]", []streamCase{
		{name: "no-tool-calls-means-no-tool-canary-scan", parts: []streamPart{{text: "Hi."}}, want: "Hi.", toolCalls: []toolWant{}},
	}, `{"mode":"block","denylist":[],"tools":{},"dlp":{"patterns":["[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}"],"canary":"]"}}`)
}
