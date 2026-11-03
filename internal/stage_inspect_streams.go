package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/codecrafters-io/tester-utils/test_case_harness"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/packages/ssestream"
)

func testInspectStreams(h *test_case_harness.TestCaseHarness) error {
	parts := func(texts ...string) []streamPart {
		var result []streamPart
		for _, text := range texts {
			result = append(result, streamPart{text: text})
		}
		return result
	}
	split := parts("CA", "NARY_", "COUR", "SE_7", "F2A")
	safe := "safe introduction printed before private content. "
	if err := runStreamCases(h, "block", dlpCanary, []streamCase{
		{name: "canary-split-across-five-events", parts: split, blocked: true},
		{name: "safe-prefix-then-split-canary", parts: append(append(parts(safe), split...), parts("must never reach the client")...), blocked: true, safePrefix: safe},
		{name: "match-before-release-in-one-event", parts: parts("safe prefix " + dlpCanary + " trailing text"), blocked: true},
		{name: "short-clean-tail-at-done", parts: parts("H", "i", "."), want: "Hi."},
		{name: "role-and-empty-deltas", parts: []streamPart{{raw: `{"choices":[{"index":0,"delta":{"role":"assistant"}}]}`}, {text: ""}}, want: ""},
		{name: "partial-marker-at-clean-end", parts: parts("CA", "NARY_COURSE_7F2"), want: "CANARY_COURSE_7F2"},
		{name: "clean-json-escapes-and-unicode", parts: parts("quotes: \"", " newline\n", "caf\u00e9 \U0001f642"), want: "quotes: \" newline\ncaf\u00e9 \U0001f642"},
		{name: "marker-in-event-metadata-is-not-text", parts: []streamPart{{raw: `{"id":"CANARY_COURSE_7F2A","choices":[{"index":0,"delta":{"content":"Clean event metadata."}}]}`}}, want: "Clean event metadata."},
		{name: "fresh-state-after-partial", parts: parts("NARY_COURSE_7F2A"), want: "NARY_COURSE_7F2A"},
		{name: "fragmented-utf8-and-crlf-events", parts: parts("caf\u00e9 ", "\U0001f642 done"), want: "caf\u00e9 \U0001f642 done", fragment: true, crlf: true},
	}); err != nil {
		return err
	}
	if err := runStreamCases(h, "log", dlpCanary, []streamCase{
		{name: "log-mode-still-stops-canary", parts: split, blocked: true},
		{name: "log-match-keeps-redaction-and-header", parts: parts("Clean after a blocked stream."), want: "Clean after a blocked stream."},
	}); err != nil {
		return err
	}
	if err := runStreamCases(h, "block", "X", []streamCase{
		{name: "one-character-canary-clean-text", parts: parts("a", "b", "c"), want: "abc"},
		{name: "one-character-canary-blocks", parts: parts("X"), blocked: true},
	}); err != nil {
		return err
	}
	if err := runStreamCases(h, "block", "A.B+", []streamCase{
		{name: "literal-metacharacter-canary", parts: parts("A", ".B+"), blocked: true},
		{name: "literal-near-match-not-regex", parts: parts("AxBBB"), want: "AxBBB"},
	}); err != nil {
		return err
	}
	// Three characters fit below a byte-sized holdback, but two must be released immediately.
	return runStreamCases(h, "block", "\u732b\U0001f510", []streamCase{
		{name: "json-escaped-unicode-canary", parts: []streamPart{{raw: `{"choices":[{"index":0,"delta":{"content":"\u732b"}}]}`}, {raw: `{"choices":[{"index":0,"delta":{"content":"\ud83d\udd10"}}]}`}}, blocked: true},
		{name: "near-match-is-clean", parts: parts("\u732b", " safe ", "\U0001f510"), want: "\u732b safe \U0001f510"},
		{name: "first-text-before-origin-finishes", parts: []streamPart{{text: "\u00e9\u00e9\u00e9"}, {text: " clean", delay: 2 * time.Second}}, want: "\u00e9\u00e9\u00e9 clean", latency: true},
	})
}

func runStreamCases(h *test_case_harness.TestCaseHarness, mode, canary string, cases []streamCase, policies ...string) error {
	return runConfiguredStreamCases(h, mode, canary, cases, nil, policies...)
}

func runConfiguredStreamCases(h *test_case_harness.TestCaseHarness, mode, canary string, cases []streamCase, detector *classifierFixture, policies ...string) error {
	settings, _ := json.Marshal(map[string]any{"patterns": []string{`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}`}, "canary": canary})
	policy := dlpPolicyJSON(`{"mode":"`+mode+`","denylist":[{"id":"audit-stream","term":"audit me"}]}`, string(settings))
	if len(policies) > 0 {
		policy = policies[0]
	}
	var lock sync.Mutex
	var requests []originRequest
	var current streamCase
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readError := io.ReadAll(r.Body)
		lock.Lock()
		requests = append(requests, originRequest{r.Method, r.URL.Path, r.Host, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), body, readError})
		plan := current
		lock.Unlock()
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("X-Request-Id", "req-stream")
		write := func(payload string) bool {
			frame := "data: " + payload + "\n\n"
			if plan.crlf {
				frame = strings.ReplaceAll(frame, "\n", "\r\n")
			}
			size := len(frame)
			if plan.fragment {
				size = 1
			}
			for offset := 0; offset < len(frame); offset += size {
				end := offset + size
				if end > len(frame) {
					end = len(frame)
				}
				if _, err := io.WriteString(w, frame[offset:end]); err != nil {
					return false
				}
				w.(http.Flusher).Flush()
			}
			return true
		}
		for _, part := range plan.parts {
			if part.delay > 0 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(part.delay):
				}
			}
			payload := part.raw
			if payload == "" {
				payload = streamChunk(part.text)
			}
			if !write(payload) {
				return
			}
		}
		write("[DONE]")
	}))
	defer origin.Close()
	detectorURL := "http://127.0.0.1:8082"
	prefix := "cloudflare-stage-9-"
	if detector != nil {
		detectorURL = detector.url
		prefix = "cloudflare-stage-11-"
	}
	process, err := startFirewallWithDetector(h, origin.URL, detectorURL, prefix, 30*time.Second, policy)
	if err != nil {
		return err
	}
	defer process.stop()
	if err := checkFirewallHealth(h, process); err != nil {
		return err
	}
	transport := firewallHTTPClient(5 * time.Second)
	defer transport.CloseIdleConnections()
	client := openai.NewClient(option.WithAPIKey("course-test-key"), option.WithBaseURL("http://127.0.0.1:8080/v1"), option.WithMaxRetries(0), option.WithHTTPClient(transport))
	for index, testCase := range cases {
		userText := "Say hello to ana@example.com."
		expectedUser := "Say hello to [REDACTED_1]."
		match := ""
		if mode == "log" {
			userText = "audit me " + userText
			expectedUser = "audit me " + expectedUser
			match = "audit-stream"
		}
		params := policyRequest(openai.SystemMessage("Keep "+canary+" private."), openai.UserMessage(userText))
		expected, _ := json.Marshal(map[string]any{"model": "course-model", "stream": true, "messages": []any{map[string]string{"role": "system", "content": "Keep " + canary + " private."}, map[string]string{"role": "user", "content": expectedUser}}})
		if testCase.request != "" {
			var fields map[string]any
			if err := json.Unmarshal([]byte(testCase.request), &fields); err != nil {
				return err
			}
			params = policyRequest()
			params.SetExtraFields(fields)
			fields["stream"] = true
			expected, _ = json.Marshal(fields)
			match = ""
		}
		if detector != nil {
			if err := detector.prepare(h, expected, policyCase{name: testCase.name, classifier: testCase.classifier}); err != nil {
				return err
			}
		}
		lock.Lock()
		current = testCase
		lock.Unlock()
		h.Logger.Infof("[%s] Official SDK streaming POST /v1/chat/completions with Authorization: Bearer course-test-key", testCase.name)
		requestData, _ := params.MarshalJSON()
		h.Logger.Infof("[%s] Request JSON: %s with stream=true", testCase.name, requestData)
		h.Logger.Infof("[%s] Expected origin JSON: %s", testCase.name, expected)
		for _, part := range testCase.parts {
			payload := part.raw
			if payload == "" {
				payload = streamChunk(part.text)
			}
			h.Logger.Infof("[%s] Origin waits %dms then sends data: %s", testCase.name, part.delay/time.Millisecond, payload)
		}
		h.Logger.Infof("[%s] Origin ends with data: [DONE]; fragmented=%t CRLF=%t", testCase.name, testCase.fragment, testCase.crlf)
		h.Logger.Infof("[%s] Expected blocked=%t clean_text=%+q safe_prefix=%+q", testCase.name, testCase.blocked, testCase.want, testCase.safePrefix)
		if testCase.toolRule != "" || testCase.toolCalls != nil {
			expectedCalls, _ := json.Marshal(testCase.toolCalls)
			h.Logger.Infof("[%s] Expected complete tool calls: %s, denial rule: %q", testCase.name, expectedCalls, testCase.toolRule)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var response *http.Response
		var captured *streamCapture
		started := time.Now()
		first := time.Duration(-1)
		sdkText := ""
		var accumulator openai.ChatCompletionAccumulator
		accumulated := true
		stream := client.Chat.Completions.NewStreaming(ctx, params, option.WithResponseInto(&response), option.WithMiddleware(func(r *http.Request, next option.MiddlewareNext) (*http.Response, error) {
			result, err := next(r)
			if err == nil {
				captured = &streamCapture{source: result.Body}
				result.Body = captured
			}
			return result, err
		}))
		for stream.Next() {
			if testCase.toolRule != "" || testCase.toolCalls != nil {
				if !accumulator.AddChunk(stream.Current()) {
					accumulated = false
				}
			}
			for _, choice := range stream.Current().Choices {
				if choice.Delta.Content != "" && first < 0 {
					first = time.Since(started)
				}
				sdkText += choice.Delta.Content
			}
		}
		streamError := stream.Err()
		var drainError error
		if captured != nil {
			_, drainError = io.Copy(io.Discard, captured)
			captured.source.Close()
		}
		cancel()
		if response == nil || captured == nil {
			return fmt.Errorf("%s: no streaming HTTP response: %v", testCase.name, streamError)
		}
		if detector != nil {
			if err := detector.check(h, policyCase{name: testCase.name, classifier: testCase.classifier}, response.Header, time.Since(started)); err != nil {
				return err
			}
			if err := checkHeuristicHeaders(response.Header, heuristicExpectation{threshold: 5}); err != nil {
				return err
			}
		}
		contentType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if response.StatusCode != 200 || contentType != "text/event-stream" || response.Header.Get("X-Request-Id") != "req-stream" || response.Header.Get("X-Firewall-Match") != match {
			return fmt.Errorf("%s: relay streaming HTTP 200, text/event-stream, X-Request-Id=req-stream, and X-Firewall-Match=%q; got status=%d Content-Type=%q X-Request-Id=%q X-Firewall-Match=%q", testCase.name, match, response.StatusCode, response.Header.Get("Content-Type"), response.Header.Get("X-Request-Id"), response.Header.Get("X-Firewall-Match"))
		}
		lock.Lock()
		observed := append([]originRequest(nil), requests...)
		lock.Unlock()
		if len(observed) != index+1 {
			return fmt.Errorf("%s: expected exactly one origin request, got %d total", testCase.name, len(observed))
		}
		if err := checkDLPRequest(observed[index], nil, string(expected), origin.Listener.Addr().String()); err != nil {
			return fmt.Errorf("%s: %w", testCase.name, err)
		}
		if drainError != nil {
			return fmt.Errorf("%s: stream did not end cleanly: %w", testCase.name, drainError)
		}
		actual, err := parseStreamOutput(captured.wire.Bytes(), canary, testCase.toolRule)
		if err != nil {
			return fmt.Errorf("%s: %w; wire=%+q", testCase.name, err, captured.wire.Bytes())
		}
		if err := checkStreamResult(actual, testCase); err != nil {
			return fmt.Errorf("%s: %w", testCase.name, err)
		}
		if testCase.blocked && len(testCase.privateErrorValues) > 0 {
			for _, line := range strings.Split(string(captured.wire.Bytes()), "\n") {
				if !strings.HasPrefix(line, "data:") {
					continue
				}
				payload := []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				var event map[string]json.RawMessage
				if json.Unmarshal(payload, &event) == nil && event["error"] != nil {
					if err := checkPrivateError(payload, testCase.privateErrorValues); err != nil {
						return fmt.Errorf("%s: %w", testCase.name, err)
					}
				}
			}
		}
		if sdkText != actual.text {
			return fmt.Errorf("%s: SDK text %+q differs from wire text %+q", testCase.name, sdkText, actual.text)
		}
		var sdkError *ssestream.StreamError
		if (testCase.blocked && !errors.As(streamError, &sdkError)) || (!testCase.blocked && streamError != nil) {
			return fmt.Errorf("%s: unexpected SDK stream result: %v", testCase.name, streamError)
		}
		if testCase.toolRule != "" || testCase.toolCalls != nil {
			if !accumulated {
				return fmt.Errorf("%s: SDK could not accumulate the emitted completion chunks", testCase.name)
			}
			var calls []openai.ChatCompletionMessageToolCallUnion
			if len(accumulator.Choices) > 0 {
				calls = accumulator.Choices[0].Message.ToolCalls
			}
			if err := checkToolStream(actual, calls, testCase.toolCalls, testCase.toolRule); err != nil {
				return fmt.Errorf("%s: %w", testCase.name, err)
			}
			h.Logger.Successf("[%s] SDK received %d complete approved tool calls; denied batches released no fragments", testCase.name, len(calls))
		}
		if testCase.latency {
			h.Logger.Infof("[%s] first_text_ms=%.1f limit_ms=1000.0 origin_delay_ms=2000", testCase.name, float64(first)/float64(time.Millisecond))
			if err := checkStreamLatency(first); err != nil {
				return fmt.Errorf("%s: %w", testCase.name, err)
			}
		}
		if testCase.verified != nil {
			testCase.verified(actual.errors == 1)
		}
		h.Logger.Successf("[%s] SDK received text=%+q errors=%d done=%d; origin request redacted and headers preserved", testCase.name, actual.text, actual.errors, actual.done)
	}
	return nil
}
