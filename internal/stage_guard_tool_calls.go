package internal

import (
	"encoding/json"

	"github.com/codecrafters-io/tester-utils/test_case_harness"
	"github.com/openai/openai-go/v3"
)

const toolsJSON = `{"http_get":{"url_argument":"url","allowed_hosts":["allowed.com"]},"get_weather":{}}`

func toolPolicyJSON(mode, settings string) string {
	var policy map[string]json.RawMessage
	json.Unmarshal([]byte(dlpPolicyJSON(`{"mode":"`+mode+`","denylist":[{"id":"audit-stream","term":"audit me"}]}`, dlpSettingsJSON)), &policy)
	policy["tools"] = json.RawMessage(settings)
	body, _ := json.Marshal(policy)
	return string(body)
}

func toolCompletion(calls ...map[string]any) string {
	body, _ := json.Marshal(map[string]any{"id": "chatcmpl-tools", "object": "chat.completion", "created": 1700000000, "model": "course-model", "choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": nil, "tool_calls": calls}, "finish_reason": "tool_calls"}}, "course_marker": "preserve-this"})
	return string(body)
}
func functionCall(id, name, arguments string) map[string]any {
	return map[string]any{"id": id, "type": "function", "function": map[string]string{"name": name, "arguments": arguments}}
}

func testGuardToolCalls(h *test_case_harness.TestCaseHarness) error {
	test := func(name, reply, rule string) policyCase {
		return policyCase{name: name, params: policyRequest(openai.UserMessage("Hello.")), rule: rule, blocked: rule != "", dlp: &dlpExpectation{response: reply, status: 200, outputBlocked: rule != "", canary: dlpCanary}}
	}
	one := func(name, tool, arguments, rule string) policyCase {
		return test(name, toolCompletion(functionCall("call_1", tool, arguments)), rule)
	}
	cases := []policyCase{
		one("reject-unlisted-run-shell", "run_shell", `{"command":"echo course"}`, "tool_not_allowed"),
		one("allow-listed-http-get", "http_get", `{ "url": "https://allowed.com/docs?next=https://evil.io", "retain":9007199254740993 }`, ""),
		one("reject-host-suffix-bypass", "http_get", `{"url":"https://allowed.com.evil.io/"}`, "tool_destination_not_allowed"),
		one("reject-userinfo-bypass", "http_get", `{"url":"https://allowed.com@evil.io/"}`, "tool_destination_not_allowed"),
		one("reject-path-is-not-host", "http_get", `{"url":"https://evil.io/allowed.com"}`, "tool_destination_not_allowed"),
		one("case-insensitive-host-with-port", "http_get", `{"url":"HTTPS://ALLOWED.COM:8443/docs"}`, ""),
		one("allow-non-url-tool", "get_weather", `{"city":"Paris","note":"https://evil.io"}`, ""),
		one("names-are-case-sensitive", "HTTP_GET", `{"url":"https://allowed.com/"}`, "tool_not_allowed"),
		one("reject-invalid-argument-json", "http_get", `{"url":`, "tool_arguments_invalid"),
		one("reject-trailing-argument-json", "http_get", `{"url":"https://allowed.com/"} {}`, "tool_arguments_invalid"),
		one("reject-array-arguments", "get_weather", `[]`, "tool_arguments_invalid"),
		one("reject-non-json-number", "get_weather", `{"value":NaN}`, "tool_arguments_invalid"),
		one("reject-null-arguments", "get_weather", `null`, "tool_arguments_invalid"),
		one("reject-missing-url", "http_get", `{"other":"https://allowed.com/"}`, "tool_arguments_invalid"),
		one("reject-non-string-url", "http_get", `{"url":42}`, "tool_arguments_invalid"),
		one("reject-null-url", "http_get", `{"url":null}`, "tool_arguments_invalid"),
		one("reject-relative-url", "http_get", `{"url":"//allowed.com/docs"}`, "tool_destination_not_allowed"),
		one("reject-non-http-scheme", "http_get", `{"url":"file://allowed.com/etc/passwd"}`, "tool_destination_not_allowed"),
		one("reject-control-characters", "http_get", `{"url":"\nhttps://allowed.com/"}`, "tool_destination_not_allowed"),
		one("reject-backslash-confusion", "http_get", `{"url":"https://allowed.com\\@evil.io/"}`, "tool_destination_not_allowed"),
		one("reject-invalid-port", "http_get", `{"url":"https://allowed.com:65536/"}`, "tool_destination_not_allowed"),
		one("reject-empty-port", "http_get", `{"url":"https://allowed.com:/"}`, "tool_destination_not_allowed"),
		one("reject-trailing-dot", "http_get", `{"url":"https://allowed.com./"}`, "tool_destination_not_allowed"),
		one("reject-escaped-host", "http_get", `{"url":"https://\u0065vil.io/allowed.com"}`, "tool_destination_not_allowed"),
		one("parse-complete-object-last-value", "http_get", `{"url":"https://allowed.com/","url":"https://evil.io/"}`, "tool_destination_not_allowed"),
		test("one-denied-call-rejects-whole-batch", toolCompletion(functionCall("call_safe", "get_weather", `{"city":"Paris"}`), functionCall("call_bad", "run_shell", `{}`)), "tool_not_allowed"),
		test("preserve-multiple-approved-calls", toolCompletion(functionCall("call_weather", "get_weather", `{"city":"Paris"}`), functionCall("call_page", "http_get", `{"url":"http://allowed.com/"}`)), ""),
		test("forbidden-tool-in-later-choice", `{"choices":[{"index":0,"message":{"role":"assistant","content":"Safe."}},{"index":1,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_bad","type":"function","function":{"name":"run_shell","arguments":"{}"}}]}}]}`, "tool_not_allowed"),
		test("reject-non-function-tool-type", `{"choices":[{"index":0,"message":{"tool_calls":[{"id":"call_custom","type":"custom","function":{"name":"get_weather","arguments":"{}"}}]}}]}`, "tool_not_allowed"),
		test("ordinary-response-without-tool-calls", policyOriginBody, ""),
		one("canary-still-precedes-tool-checks", "run_shell", `{"command":"CANARY_COURSE_7F2A"}`, "canary_leak"),
	}
	// Request tool definitions do not authorize an action absent from trusted policy.
	cases[0].params.SetExtraFields(map[string]any{"tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "run_shell", "description": "Return a dummy result", "parameters": map[string]any{"type": "object"}}}}})
	if err := runPolicyCases(h, toolPolicyJSON("block", toolsJSON), "firewall-stage-10-", cases); err != nil {
		return err
	}
	changed := `{"fetch_page":{"url_argument":"target","allowed_hosts":["docs.example.org"]},"run_shell":{}}`
	if err := runPolicyCases(h, toolPolicyJSON("log", changed), "firewall-stage-10-", []policyCase{
		one("use-supplied-tool-and-url-field", "fetch_page", `{"target":"https://DOCS.EXAMPLE.ORG/","url":"https://evil.io"}`, ""),
		one("previous-allowlist-is-not-authority", "http_get", `{"url":"https://allowed.com/"}`, "tool_not_allowed"),
		one("configured-run-shell-is-allowed", "run_shell", `{"command":"echo course"}`, ""),
		one("log-mode-does-not-authorize-destination", "fetch_page", `{"target":"https://docs.example.org.evil.io/"}`, "tool_destination_not_allowed"),
	}); err != nil {
		return err
	}
	if err := runPolicyCases(h, toolPolicyJSON("block", `{}`), "firewall-stage-10-", []policyCase{one("empty-tool-allowlist-denies-all", "get_weather", `{}`, "tool_not_allowed")}); err != nil {
		return err
	}
	return runToolStreamCases(h)
}
