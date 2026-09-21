package helps_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/tidwall/gjson"
)

func TestBuildToolMap(t *testing.T) {
	tools := []helps.TraeToolDefinition{
		{Name: "Bash", Description: "Run bash"},
		{Name: "ReadFile", Description: "Read a file"},
	}
	m := helps.BuildToolMap(tools)
	if m["bash"] != "Bash" {
		t.Fatalf("expected m[bash]=Bash, got %s", m["bash"])
	}
	if m["run_command"] != "Bash" {
		t.Fatalf("expected m[run_command]=Bash, got %s", m["run_command"])
	}
	if m["read_file"] != "ReadFile" {
		t.Fatalf("expected m[read_file]=ReadFile, got %s", m["read_file"])
	}
}

func TestFormatTraeMessagesWithTools(t *testing.T) {
	payloadJSON := `{
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "list directory"},
			{
				"role": "assistant",
				"content": "Running command",
				"tool_calls": [
					{
						"id": "call_123",
						"type": "function",
						"function": {
							"name": "Bash",
							"arguments": "{\"command\":\"ls -la\"}"
						}
					}
				]
			},
			{
				"role": "tool",
				"tool_call_id": "call_123",
				"content": "file1.txt\nfile2.txt"
			}
		],
		"tools": [
			{
				"type": "function",
				"function": {
					"name": "Bash",
					"description": "Execute bash command",
					"parameters": {
						"type": "object",
						"properties": {
							"command": {"type": "string"}
						}
					}
				}
			}
		]
	}`

	root := gjson.Parse(payloadJSON)
	messages, toolMap := helps.FormatTraeMessagesWithTools(root)

	if len(toolMap) == 0 || toolMap["bash"] != "Bash" {
		t.Fatalf("expected toolMap to contain bash, got %v", toolMap)
	}

	// Should have at least system, user, assistant, user(tool_result)
	if len(messages) < 4 {
		t.Fatalf("expected at least 4 messages, got %d", len(messages))
	}

	// 1. System prompt should contain <available_tools>
	sysMsg := messages[0]
	sysContent := ""
	if parts, ok := sysMsg["content"].([]map[string]any); ok {
		sysContent = parts[0]["text"].(string)
	}
	if !strings.Contains(sysContent, "<available_tools>") || !strings.Contains(sysContent, "Bash") {
		t.Fatalf("expected system prompt to contain <available_tools> and Bash, got %s", sysContent)
	}

	// 2. Assistant message should contain <toolcall>
	asstMsg := messages[2]
	asstContent := ""
	if parts, ok := asstMsg["content"].([]map[string]any); ok {
		asstContent = parts[0]["text"].(string)
	}
	if !strings.Contains(asstContent, "<toolcall>") || !strings.Contains(asstContent, "Bash") {
		t.Fatalf("expected assistant message to contain <toolcall>, got %s", asstContent)
	}

	// 3. Tool message converted to user role with <tool_result>
	toolResultMsg := messages[3]
	if toolResultMsg["role"] != "user" {
		t.Fatalf("expected role user for tool_result message, got %s", toolResultMsg["role"])
	}
	trContent := ""
	if parts, ok := toolResultMsg["content"].([]map[string]any); ok {
		trContent = parts[0]["text"].(string)
	}
	if !strings.Contains(trContent, "<tool_result for=\"Bash\"") || !strings.Contains(trContent, "file1.txt") {
		t.Fatalf("expected tool result format, got %s", trContent)
	}
}

func TestParseToolcallContent(t *testing.T) {
	toolMap := map[string]string{
		"bash": "Bash",
		"read": "Read",
	}

	// Test 1: standard JSON
	json1 := `{"name": "Bash", "params": {"command": "git status"}}`
	call1, ok := helps.ParseToolcallContent(json1, toolMap)
	if !ok || call1.Name != "Bash" {
		t.Fatalf("failed to parse standard JSON, got %+v", call1)
	}
	if !strings.Contains(call1.Args, "git status") {
		t.Fatalf("expected args to contain git status, got %s", call1.Args)
	}

	// Test 2: embedded JSON with function.arguments
	json2 := `Some text before {"function": {"name": "bash", "arguments": "{\"command\":\"pwd\"}"}} text after`
	call2, ok := helps.ParseToolcallContent(json2, toolMap)
	if !ok || call2.Name != "Bash" {
		t.Fatalf("failed to parse embedded JSON, got %+v", call2)
	}

	// Test 3: XML with <param name="...">
	xml1 := `bash
<param name="command">whoami</param>`
	call3, ok := helps.ParseToolcallContent(xml1, toolMap)
	if !ok || call3.Name != "Bash" {
		t.Fatalf("failed to parse xml param style, got %+v", call3)
	}
	if !strings.Contains(call3.Args, "whoami") {
		t.Fatalf("expected args to contain whoami, got %s", call3.Args)
	}
}

func TestExtractAndStripToolCalls(t *testing.T) {
	toolMap := map[string]string{
		"bash": "Bash",
	}

	text := `I will run the command for you.
<toolcall>
{"name": "Bash", "params": {"command": "ls"}}
</toolcall>
Please wait for the results.`

	calls := helps.ExtractToolCallsFromText(text, toolMap)
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}
	if calls[0].Name != "Bash" {
		t.Fatalf("expected tool call name Bash, got %s", calls[0].Name)
	}

	stripped := helps.StripToolCallsFromText(text)
	if strings.Contains(stripped, "<toolcall>") || strings.Contains(stripped, "</toolcall>") {
		t.Fatalf("stripped text should not contain toolcall tags, got %s", stripped)
	}
	if !strings.Contains(stripped, "I will run the command") || !strings.Contains(stripped, "Please wait") {
		t.Fatalf("stripped text missing other sentences: %s", stripped)
	}
}

func TestToolCallStreamFilter(t *testing.T) {
	toolMap := map[string]string{
		"bash": "Bash",
	}
	filter := helps.NewToolCallStreamFilter(toolMap)

	// Stream chunks arriving piecemeal
	chunks := []string{
		"Let me check the status.\n",
		"<tool",
		"call>\n{\"name\": ",
		"\"bash\", \"params\": {\"command\": \"git ",
		"diff\"}}\n</tool",
		"call>\nDone.",
	}

	var visibleText strings.Builder
	var allCalls []helps.TraeToolCall

	for _, c := range chunks {
		txt, calls := filter.Feed(c)
		visibleText.WriteString(txt)
		allCalls = append(allCalls, calls...)
	}
	flushTxt, finalCalls := filter.Flush()
	visibleText.WriteString(flushTxt)
	allCalls = append(allCalls, finalCalls...)

	if len(allCalls) != 1 {
		t.Fatalf("expected 1 call extracted from stream, got %d", len(allCalls))
	}
	if allCalls[0].Name != "Bash" {
		t.Fatalf("expected tool call name Bash, got %s", allCalls[0].Name)
	}
	if !strings.Contains(allCalls[0].Args, "git diff") {
		t.Fatalf("expected args to contain git diff, got %s", allCalls[0].Args)
	}

	outText := visibleText.String()
	if strings.Contains(outText, "<toolcall>") || strings.Contains(outText, "</toolcall>") {
		t.Fatalf("visible text leaked toolcall tag: %s", outText)
	}
	if !strings.Contains(outText, "Let me check the status") || !strings.Contains(outText, "Done.") {
		t.Fatalf("missing normal text in output: %s", outText)
	}
	if !filter.HasEmittedCalls() {
		t.Fatalf("filter.HasEmittedCalls should be true")
	}
}

func TestFormatOpenAIStreamToolCallChunk(t *testing.T) {
	calls := []helps.TraeToolCall{
		{
			Index: 0,
			ID:    "call_abc123",
			Name:  "Bash",
			Args:  `{"command":"ls"}`,
		},
	}
	b := helps.FormatOpenAIStreamToolCallChunk("chatcmpl-1", "glm-5.3-flash", calls)
	if len(b) == 0 {
		t.Fatalf("expected non-empty chunk bytes")
	}
	parsed := gjson.ParseBytes(b)
	tc := parsed.Get("choices.0.delta.tool_calls.0")
	if !tc.Exists() {
		t.Fatalf("tool_calls not found in chunk: %s", string(b))
	}
	if tc.Get("function.name").String() != "Bash" {
		t.Fatalf("expected Bash, got %s", tc.Get("function.name").String())
	}
	if tc.Get("id").String() != "call_abc123" {
		t.Fatalf("expected call_abc123, got %s", tc.Get("id").String())
	}
}

func TestFormatOpenAINonStreamResponseWithTools(t *testing.T) {
	calls := []helps.TraeToolCall{
		{
			Index: 0,
			ID:    "call_test_01",
			Name:  "Bash",
			Args:  `{"command":"date"}`,
		},
	}
	respJSON := helps.FormatOpenAINonStreamResponseWithTools("chatcmpl-2", "glm-5.3-flash", "running date", "thinking about time", calls, nil)
	parsed := gjson.ParseBytes(respJSON)

	if parsed.Get("choices.0.finish_reason").String() != "tool_calls" {
		t.Fatalf("expected finish_reason tool_calls, got %s", parsed.Get("choices.0.finish_reason").String())
	}
	if parsed.Get("choices.0.message.tool_calls.0.function.name").String() != "Bash" {
		t.Fatalf("expected Bash tool call in message")
	}

	var m map[string]any
	if err := json.Unmarshal(respJSON, &m); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
}
