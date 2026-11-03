package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

type streamPart struct {
	text  string
	raw   string
	delay time.Duration
}

type streamCase struct {
	privateErrorValues []string
	request            string
	classifier         *classifierExpectation
	verified           func(bool)
	name               string
	parts              []streamPart
	want               string
	safePrefix         string
	blocked            bool
	fragment           bool
	crlf               bool
	latency            bool
	toolRule           string
	toolCalls          []toolWant
}

func streamChunk(text string) string {
	body, _ := json.Marshal(map[string]any{"id": "chatcmpl-origin-stream", "object": "chat.completion.chunk", "created": 1700000000, "model": "course-model", "choices": []any{map[string]any{"index": 0, "delta": map[string]string{"content": text}, "finish_reason": nil}}})
	return string(body)
}

// The SDK closes on its first terminal event. Keep reading afterward to reject extra wire events.
type streamCapture struct {
	source io.ReadCloser
	wire   bytes.Buffer
}

func (c *streamCapture) Read(p []byte) (int, error) {
	n, err := c.source.Read(p)
	c.wire.Write(p[:n])
	return n, err
}
func (c *streamCapture) Close() error { return nil }

type streamResult struct {
	text   string
	errors int
	done   int
	tools  int
	rule   string
}

func parseStreamOutput(wire []byte, canary string, allowedRules ...string) (streamResult, error) {
	var result streamResult
	if !utf8.Valid(wire) {
		return result, fmt.Errorf("SSE output must be valid UTF-8")
	}
	body := strings.ReplaceAll(string(wire), "\r\n", "\n")
	if !strings.HasSuffix(body, "\n\n") {
		return result, fmt.Errorf("terminate each SSE event with a blank line")
	}
	terminal := false
	for _, frame := range strings.Split(strings.TrimSuffix(body, "\n\n"), "\n\n") {
		if frame == "" {
			continue
		}
		if terminal {
			return result, fmt.Errorf("send no events after the error or [DONE]")
		}
		var payload string
		lines := 0
		for _, line := range strings.Split(frame, "\n") {
			if strings.HasPrefix(line, "data:") {
				payload = strings.TrimPrefix(line, "data:")
				payload = strings.TrimPrefix(payload, " ")
				lines++
			} else if !strings.HasPrefix(line, "event:") {
				return result, fmt.Errorf("expected a data: event, got %+q", line)
			}
		}
		if lines != 1 {
			return result, fmt.Errorf("each event must have one data: line")
		}
		if payload == "[DONE]" {
			result.done++
			terminal = true
			continue
		}
		var envelope struct {
			Error   *struct{ Message, Type, Rule string } `json:"error"`
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					Content   string            `json:"content"`
					ToolCalls []json.RawMessage `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
			return result, fmt.Errorf("invalid event JSON: %w", err)
		}
		if envelope.Error != nil {
			item := envelope.Error
			var value any
			json.Unmarshal([]byte(payload), &value)
			canonical, _ := json.Marshal(value)
			validRule := item.Rule == "canary_leak"
			for _, rule := range allowedRules {
				if item.Rule == rule {
					validRule = true
				}
			}
			if item.Type != "firewall_block" || !validRule || item.Message == "" || bytes.Contains(canonical, []byte(canary)) {
				return result, fmt.Errorf("stream error must name an allowed firewall rule and contain no marker")
			}
			result.rule = item.Rule
			result.errors++
			terminal = true
			continue
		}
		for _, choice := range envelope.Choices {
			if choice.Index != 0 {
				return result, fmt.Errorf("this stage streams only choice index 0")
			}
			result.text += choice.Delta.Content
			result.tools += len(choice.Delta.ToolCalls)
		}
	}
	return result, nil
}

func checkStreamResult(actual streamResult, testCase streamCase) error {
	if testCase.blocked {
		rule := "canary_leak"
		if testCase.toolRule != "" {
			rule = testCase.toolRule
		}
		if actual.errors != 1 || actual.done != 0 || !strings.HasPrefix(testCase.safePrefix, actual.text) {
			return fmt.Errorf("expected one %s error, no [DONE], and only a safe prefix of %+q; got text=%+q errors=%d done=%d; hold the last L-1 characters before releasing text", rule, testCase.safePrefix, actual.text, actual.errors, actual.done)
		}
	} else if actual.errors != 0 || actual.done != 1 || actual.text != testCase.want {
		return fmt.Errorf("expected complete clean text %+q followed by one [DONE]; got text=%+q errors=%d done=%d; flush the retained tail when [DONE] arrives", testCase.want, actual.text, actual.errors, actual.done)
	}
	return nil
}

func checkStreamLatency(first time.Duration) error {
	if first < 0 || first >= time.Second {
		return fmt.Errorf("first_text_ms=%.1f limit_ms=1000.0: release and flush safe text before the two-second origin finishes; do not buffer the whole response", float64(first)/float64(time.Millisecond))
	}
	return nil
}
