package internal

import (
	"encoding/json"
	"fmt"

	"github.com/openai/openai-go/v3"
)

type toolWant struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

func checkToolStream(actual streamResult, calls []openai.ChatCompletionMessageToolCallUnion, expected []toolWant, rule string) error {
	if rule != "" {
		if actual.rule != rule || actual.tools != 0 || len(calls) != 0 {
			return fmt.Errorf("expected rule %s and no tool-call fragments before denial; got rule=%q wire_fragments=%d SDK_calls=%d", rule, actual.rule, actual.tools, len(calls))
		}
		return nil
	}
	if len(calls) != len(expected) {
		return fmt.Errorf("expected %d complete approved tool calls, SDK received %d; preserve tool IDs, names, arguments, and index ordering", len(expected), len(calls))
	}
	for index, want := range expected {
		got := calls[index]
		if got.Type != "function" || got.ID != want.ID || got.Function.Name != want.Name || got.Function.Arguments != want.Arguments {
			return fmt.Errorf("tool call %d: expected id=%q name=%q arguments=%+q, got id=%q type=%q name=%q arguments=%+q", index, want.ID, want.Name, want.Arguments, got.ID, got.Type, got.Function.Name, got.Function.Arguments)
		}
	}
	return nil
}

func toolDelta(text string, calls ...map[string]any) string {
	delta := map[string]any{}
	if text != "" {
		delta["content"] = text
	}
	if len(calls) > 0 {
		delta["tool_calls"] = calls
	}
	body, _ := json.Marshal(map[string]any{"id": "chatcmpl-tool-stream", "object": "chat.completion.chunk", "created": 1700000000, "model": "course-model", "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": nil}}})
	return string(body)
}
func toolFragment(index int, id, name, arguments string) map[string]any {
	call := map[string]any{"index": index, "function": map[string]string{"name": name, "arguments": arguments}}
	if id != "" {
		call["id"] = id
		call["type"] = "function"
	}
	return call
}
