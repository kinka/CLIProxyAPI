package executor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	traeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/trae"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator/claude/openai/chat-completions"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator/openai/claude"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestTraeExecutorIdentifier(t *testing.T) {
	exec := NewTraeExecutor(&config.Config{})
	if id := exec.Identifier(); id != "trae" {
		t.Fatalf("expected identifier 'trae', got %q", id)
	}
}

func TestTraeExecutorRequestToFormat(t *testing.T) {
	exec := NewTraeExecutor(&config.Config{})
	req := cliproxyexecutor.Request{}

	optsClaude := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude}
	if f := exec.RequestToFormat(req, optsClaude); f != sdktranslator.FormatClaude {
		t.Fatalf("expected FormatClaude, got %v", f)
	}

	optsOpenAIResp := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
	if f := exec.RequestToFormat(req, optsOpenAIResp); f != sdktranslator.FormatOpenAIResponse {
		t.Fatalf("expected FormatOpenAIResponse, got %v", f)
	}

	optsOpenAI := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI}
	if f := exec.RequestToFormat(req, optsOpenAI); f != sdktranslator.FormatOpenAI {
		t.Fatalf("expected FormatOpenAI, got %v", f)
	}
}

func TestTraeModelResolution(t *testing.T) {
	tests := []struct {
		input      string
		wantFunc   string
		wantConfig string
	}{
		{"auto", "inline_chat", ""},
		{"trae-auto", "inline_chat", ""},
		{"inline_chat", "inline_chat", ""},
		{"glm-5.3", "solo_agent", "glm-5.3"},
		{"glm-5.3-flash", "solo_agent", "glm-5.3-flash"},
		{"gf", "solo_agent", "glm-5.3-flash"},
		{"glm-5.2", "solo_agent", "glm-5.2"},
		{"glm-5.1", "chat_v3", "glm-5.1"},
		{"glm-5", "chat_v3", "glm-5"},
		{"doubao-seed-code", "solo_agent", "Doubao_1_6"},
		{"doubao-1-6", "solo_agent", "Doubao_1_6"},
		{"doubao", "solo_agent", "Doubao_1_6"},
		{"DeepSeek-V4-Pro", "solo_agent", "DeepSeek-V4-Pro-Official"},
		{"deepseek-r1", "chat_v3", "custom_model_deepseek_reasoner"},
		{"qwen-3.7-plus", "solo_agent", "qwen-3.7-plus"},
		{"qwen", "solo_agent", "qwen-3.7-plus"},
		{"kimi-k2.6", "solo_agent", "kimi-k2.6"},
		{"k2.6", "solo_agent", "kimi-k2.6"},
		{"kimi-k3", "solo_agent", "kimi-k3"},
		{"k3", "solo_agent", "kimi-k3"},
		{"kimi-k2.8-preview", "solo_agent", "kimi-k2.8-preview"},
		{"kimi-k2.8", "solo_agent", "kimi-k2.8-preview"},
		{"k2.8", "solo_agent", "kimi-k2.8-preview"},
		{"deepseek-v4.1-flash", "solo_agent", "DeepSeek-V4.1-Flash"},
		{"dsf", "solo_agent", "DeepSeek-V4.1-Flash"},
		{"deepseek-v4-pro-official", "solo_agent", "DeepSeek-V4-Pro-Official"},
		{"dsp", "solo_agent", "DeepSeek-V4-Pro-Official"},
		{"deepseek-v4-flash-official", "solo_agent", "DeepSeek-V4-Flash-Official"},
		{"qwen3.8-max", "solo_agent", "qwen3.8-max"},
		{"doubao-seed-evolving", "solo_agent", "Doubao-Seed-Evolving"},
		{"claude-3-7-sonnet", "solo_agent", "glm-5.3-flash"},
		{"claude-3-5-haiku", "chat_v3", "glm-5.1"},
		{"gpt-4o", "chat_v3", "custom_model_gpt-5"},
		{"gemini-2.0-flash", "chat_v3", "custom_model_gemini"},
		{"custom-unknown-model", "chat_v3", "custom-unknown-model"},
	}

	for _, tt := range tests {
		fn, cfg := helps.ResolveTraeModel(tt.input)
		if fn != tt.wantFunc || cfg != tt.wantConfig {
			t.Errorf("ResolveTraeModel(%q) = (%q, %q), want (%q, %q)", tt.input, fn, cfg, tt.wantFunc, tt.wantConfig)
		}
	}
}

func TestBuildTraeRequestBody(t *testing.T) {
	rawJSON := `{
		"messages": [
			{"role": "system", "content": "You are a helpful assistant"},
			{"role": "user", "content": [{"type": "text", "text": "Hello world"}]}
		],
		"max_tokens": 4096,
		"temperature": 0.7,
		"top_p": 0.95
	}`

	storage := &traeauth.TraeTokenStorage{
		UserID:   "419608832",
		DeviceID: "dev-12345",
	}
	body, modelName, err := helps.BuildTraeRequestBody([]byte(rawJSON), "glm-5.2", storage, true)
	if err != nil {
		t.Fatalf("BuildTraeRequestBody failed: %v", err)
	}
	if modelName != "glm-5.2" {
		t.Fatalf("expected modelName 'glm-5.2', got %q", modelName)
	}

	parsed := gjson.ParseBytes(body)
	// Mainstream models are routed through solo_agent so tool calling works.
	if parsed.Get("function").String() != "solo_agent" {
		t.Errorf("expected function solo_agent, got %q", parsed.Get("function").String())
	}
	if parsed.Get("config_name").String() != "glm-5.2" {
		t.Errorf("expected config_name glm-5.2, got %q", parsed.Get("config_name").String())
	}
	if !parsed.Get("stream").Bool() {
		t.Errorf("expected stream true")
	}
	if parsed.Get("user_id").String() != "419608832" {
		t.Errorf("expected user_id 419608832, got %q", parsed.Get("user_id").String())
	}
	if parsed.Get("device_id").String() != "dev-12345" {
		t.Errorf("expected device_id dev-12345, got %q", parsed.Get("device_id").String())
	}
	if !strings.HasPrefix(parsed.Get("session_id").String(), "sess_") {
		t.Errorf("expected session_id to start with sess_, got %q", parsed.Get("session_id").String())
	}
	if parsed.Get("max_tokens").Int() != 4096 {
		t.Errorf("expected max_tokens 4096, got %d", parsed.Get("max_tokens").Int())
	}
	if parsed.Get("temperature").Float() != 0.7 {
		t.Errorf("expected temperature 0.7, got %f", parsed.Get("temperature").Float())
	}

	msgs := parsed.Get("messages").Array()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].Get("role").String() != "system" {
		t.Errorf("expected message 0 role system")
	}
	content0 := msgs[0].Get("content").Array()
	if len(content0) != 1 || content0[0].Get("text").String() != "You are a helpful assistant" {
		t.Errorf("unexpected content0: %v", content0)
	}
}

func TestParseTraeSSELine(t *testing.T) {
	var currentEvent string

	// Event line
	p := helps.ParseTraeSSELine("event: output", &currentEvent)
	if p == nil || p.Type != "event_name" || currentEvent != "output" {
		t.Fatalf("expected event_name 'output', got %v, currentEvent=%s", p, currentEvent)
	}

	// Data line with content and reasoning
	dataLine := `data: {"content":"Hello!","reasoning":"Thinking step 1"}`
	p = helps.ParseTraeSSELine(dataLine, &currentEvent)
	if p == nil || p.Type != "text" || p.Content != "Hello!" || p.Reasoning != "Thinking step 1" {
		t.Fatalf("unexpected parsed text chunk: %+v", p)
	}

	// Legacy data format with response and reasoning_content
	dataLineLegacy := `data: {"response":" World","reasoning_content":"Thinking step 2"}`
	p = helps.ParseTraeSSELine(dataLineLegacy, &currentEvent)
	if p == nil || p.Type != "text" || p.Content != " World" || p.Reasoning != "Thinking step 2" {
		t.Fatalf("unexpected parsed legacy text chunk: %+v", p)
	}

	// Token usage event
	helps.ParseTraeSSELine("event: token_usage", &currentEvent)
	usageLine := `data: {"prompt_tokens":100,"completion_tokens":50,"total_tokens":150,"reasoning_tokens":20}`
	p = helps.ParseTraeSSELine(usageLine, &currentEvent)
	if p == nil || p.Type != "token_usage" || p.TokenUsage == nil {
		t.Fatalf("unexpected token usage chunk: %+v", p)
	}
	if p.TokenUsage.PromptTokens != 100 || p.TokenUsage.CompletionTokens != 50 || p.TokenUsage.ReasoningTokens != 20 {
		t.Errorf("unexpected usage counts: %+v", p.TokenUsage)
	}

	// Done event
	helps.ParseTraeSSELine("event: done", &currentEvent)
	doneLine := `data: {"finish_reason":"stop"}`
	p = helps.ParseTraeSSELine(doneLine, &currentEvent)
	if p == nil || p.Type != "done" || p.FinishReason != "stop" {
		t.Fatalf("unexpected done chunk: %+v", p)
	}

	// [DONE] terminal
	p = helps.ParseTraeSSELine("data: [DONE]", &currentEvent)
	if p == nil || p.Type != "done" {
		t.Fatalf("expected done for [DONE], got %+v", p)
	}
}

func TestTraeExecutorExecuteAndStream(t *testing.T) {
	// Mock server mimicking Trae SSE responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != TraeChatPath {
			http.NotFound(w, r)
			return
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Cloud-IDE-JWT ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}

		lines := []string{
			"event: output\n",
			`data: {"reasoning":"Let me think."}` + "\n\n",
			"event: output\n",
			`data: {"content":"Hello there!"}` + "\n\n",
			"event: token_usage\n",
			`data: {"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"reasoning_tokens":3}` + "\n\n",
			"event: done\n",
			`data: {"finish_reason":"stop"}` + "\n\n",
			"data: [DONE]\n\n",
		}

		for _, l := range lines {
			_, _ = w.Write([]byte(l))
			flusher.Flush()
			time.Sleep(2 * time.Millisecond)
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	exec := NewTraeExecutor(cfg)

	auth := &cliproxyauth.Auth{
		ID:       "test-trae",
		Provider: "trae",
		Storage: &traeauth.TraeTokenStorage{
			AccessToken: "test-token-12345",
			Host:        server.URL,
			Edition:     "cn",
			MachineID:   "test-machine-id",
			DeviceID:    "1234567890123456789",
		},
	}

	reqPayload := []byte(`{"messages":[{"role":"user","content":"Hi"}],"model":"glm-5.2"}`)

	// Test Non-Stream Execute
	ctx := context.Background()
	req := cliproxyexecutor.Request{
		Model:   "glm-5.2",
		Payload: reqPayload,
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
	}

	resp, err := exec.Execute(ctx, auth, req, opts)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	var openAIResp map[string]any
	if err := json.Unmarshal(resp.Payload, &openAIResp); err != nil {
		t.Fatalf("failed to unmarshal non-stream response: %v", err)
	}
	choices, _ := openAIResp["choices"].([]any)
	if len(choices) == 0 {
		t.Fatalf("expected non-empty choices: %v", openAIResp)
	}
	msg, _ := choices[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "Hello there!" {
		t.Errorf("expected message content 'Hello there!', got %v", msg["content"])
	}
	if msg["reasoning_content"] != "Let me think." {
		t.Errorf("expected reasoning_content 'Let me think.', got %v", msg["reasoning_content"])
	}

	// Test Stream ExecuteStream
	streamRes, err := exec.ExecuteStream(ctx, auth, req, opts)
	if err != nil {
		t.Fatalf("ExecuteStream failed: %v", err)
	}

	var receivedChunks [][]byte
	for chunk := range streamRes.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error: %v", chunk.Err)
		}
		receivedChunks = append(receivedChunks, chunk.Payload)
	}

	if len(receivedChunks) == 0 {
		t.Fatalf("expected stream chunks, got none")
	}
}

func TestTraeModelPrefersRawChat(t *testing.T) {
	rawModels := []string{"kimi-k3", "k3", "kimi-k2.8-preview", "k2.8", "deepseek-v4.1-flash", "dsf", "glm-5.3", "gf", "glm-5.2", "qwen-3.7-plus", "qwen", "doubao", "Doubao_1_6"}
	for _, m := range rawModels {
		if !helps.ModelPrefersRawChat(m) {
			t.Errorf("expected ModelPrefersRawChat(%q) = true, got false", m)
		}
	}

	nonRawModels := []string{"glm-5.1", "trae-auto", "kimi-k2.5", "minimax-m3"}
	for _, m := range nonRawModels {
		if helps.ModelPrefersRawChat(m) {
			t.Errorf("expected ModelPrefersRawChat(%q) = false, got true", m)
		}
	}
}

func TestBuildTraeRawChatRequestBody(t *testing.T) {
	rawJSON := `{"messages":[{"role":"user","content":"ping"}],"model":"kimi-k3"}`
	storage := &traeauth.TraeTokenStorage{
		UserID:   "user-1",
		DeviceID: "dev-1",
	}
	body, configName, err := helps.BuildTraeRawChatRequestBody([]byte(rawJSON), "kimi-k3", storage, true)
	if err != nil {
		t.Fatalf("BuildTraeRawChatRequestBody failed: %v", err)
	}
	if configName != "kimi-k3" {
		t.Errorf("expected configName kimi-k3, got %s", configName)
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to unmarshal raw chat body: %v", err)
	}
	if parsed["function"] != "solo_agent" || parsed["raw_chat_function"] != "solo_agent" {
		t.Errorf("expected function and raw_chat_function = solo_agent, got %v, %v", parsed["function"], parsed["raw_chat_function"])
	}
	if parsed["config_name"] != "kimi-k3" || parsed["model_name"] != "kimi-k3__dev" {
		t.Errorf("expected config_name kimi-k3, model_name kimi-k3__dev, got %v, %v", parsed["config_name"], parsed["model_name"])
	}
}

func TestTraeExecutorFallbackOn4001(t *testing.T) {
	var rawChatHit, chatV3Hit int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}

		if r.URL.Path == TraeRawChatPath {
			rawChatHit++
			// Simulate early 4001 error on raw chat
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: error\n"))
			_, _ = w.Write([]byte(`data: {"error_code":4001,"error_message":"model not supported in raw chat"}` + "\n\n"))
			flusher.Flush()
			return
		}

		if r.URL.Path == TraeChatPath {
			chatV3Hit++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: output\n"))
			_, _ = w.Write([]byte(`data: {"content":"fallback success"}` + "\n\n"))
			_, _ = w.Write([]byte("event: done\n"))
			_, _ = w.Write([]byte(`data: {"finish_reason":"stop"}` + "\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			flusher.Flush()
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := &config.Config{}
	exec := NewTraeExecutor(cfg)
	auth := &cliproxyauth.Auth{
		ID:       "test-trae",
		Provider: "trae",
		Storage: &traeauth.TraeTokenStorage{
			AccessToken: "test-token",
			Host:        server.URL,
		},
	}

	ctx := context.Background()
	req := cliproxyexecutor.Request{
		Model:   "kimi-k3", // prefers raw chat first
		Payload: []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
	}

	// 1. Test streaming fallback
	streamRes, err := exec.ExecuteStream(ctx, auth, req, opts)
	if err != nil {
		t.Fatalf("stream fallback failed: %v", err)
	}
	var chunks [][]byte
	for c := range streamRes.Chunks {
		if c.Err != nil {
			t.Fatalf("unexpected chunk err: %v", c.Err)
		}
		chunks = append(chunks, c.Payload)
	}
	if len(chunks) == 0 {
		t.Fatalf("expected chunks after fallback, got none")
	}
	if rawChatHit == 0 || chatV3Hit == 0 {
		t.Errorf("expected both raw_chat and chat_v3 to be hit in fallback, got raw=%d, chat_v3=%d", rawChatHit, chatV3Hit)
	}

	// 2. Test non-streaming fallback
	rawChatHit = 0
	chatV3Hit = 0
	resp, err := exec.Execute(ctx, auth, req, opts)
	if err != nil {
		t.Fatalf("non-stream fallback failed: %v", err)
	}
	if !strings.Contains(string(resp.Payload), "fallback success") {
		t.Errorf("expected payload to contain fallback success, got %s", string(resp.Payload))
	}
	if rawChatHit == 0 || chatV3Hit == 0 {
		t.Errorf("expected both raw_chat and chat_v3 to be hit in non-stream fallback, got raw=%d, chat_v3=%d", rawChatHit, chatV3Hit)
	}
}

func TestTraeExecutorToolCallsStreamingAndNonStreaming(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}

		w.WriteHeader(http.StatusOK)
		lines := []string{
			"event: output\n",
			`data: {"content":"I will run the command.\n<toolcall>{\"name\": \"bash\", \"params\": {\"command\": \"pwd\"}}</toolcall>\nPlease wait."}` + "\n\n",
			"event: done\n",
			`data: {"finish_reason":"stop"}` + "\n\n",
			"data: [DONE]\n\n",
		}
		for _, l := range lines {
			_, _ = w.Write([]byte(l))
			flusher.Flush()
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	exec := NewTraeExecutor(cfg)
	auth := &cliproxyauth.Auth{
		ID:       "test-trae-tool",
		Provider: "trae",
		Storage: &traeauth.TraeTokenStorage{
			AccessToken: "test-token",
			Host:        server.URL,
		},
	}

	ctx := context.Background()
	payload := []byte(`{
		"model": "glm-5.3-flash",
		"messages": [{"role": "user", "content": "where am I?"}],
		"tools": [
			{
				"type": "function",
				"function": {
					"name": "Bash",
					"description": "Run shell command",
					"parameters": {
						"type": "object",
						"properties": {"command": {"type": "string"}}
					}
				}
			}
		]
	}`)

	// 1. Non-streaming test
	req := cliproxyexecutor.Request{
		Model:   "glm-5.3-flash",
		Payload: payload,
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
	}
	resp, err := exec.Execute(ctx, auth, req, opts)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	respParsed := gjson.ParseBytes(resp.Payload)
	if respParsed.Get("choices.0.finish_reason").String() != "tool_calls" {
		t.Errorf("expected finish_reason tool_calls, got %q", respParsed.Get("choices.0.finish_reason").String())
	}
	tcName := respParsed.Get("choices.0.message.tool_calls.0.function.name").String()
	if tcName != "Bash" {
		t.Errorf("expected tool_call name Bash, got %q", tcName)
	}

	// 2. Streaming test with Claude source format (simulating Claude Code)
	claudePayload := []byte(`{
		"model": "glm-5.3-flash",
		"stream": true,
		"messages": [{"role": "user", "content": "where am I?"}],
		"tools": [
			{
				"name": "Bash",
				"description": "Run shell command",
				"input_schema": {
					"type": "object",
					"properties": {"command": {"type": "string"}}
				}
			}
		]
	}`)
	claudeReq := cliproxyexecutor.Request{
		Model:   "glm-5.3-flash",
		Payload: claudePayload,
	}
	claudeOpts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
	}
	streamRes, err := exec.ExecuteStream(ctx, auth, claudeReq, claudeOpts)
	if err != nil {
		t.Fatalf("stream execute failed: %v", err)
	}

	var fullSSE strings.Builder
	for c := range streamRes.Chunks {
		if c.Err != nil {
			t.Fatalf("unexpected stream err: %v", c.Err)
		}
		fullSSE.Write(c.Payload)
	}
	sseStr := fullSSE.String()

	// Verify Claude SSE contains tool_use and stop_reason: tool_use
	if !strings.Contains(sseStr, `"type":"tool_use"`) {
		t.Errorf("expected sse stream to contain tool_use block, got:\n%s", sseStr)
	}
	if !strings.Contains(sseStr, `"name":"Bash"`) {
		t.Errorf("expected sse stream to contain name Bash, got:\n%s", sseStr)
	}
	if !strings.Contains(sseStr, `"stop_reason":"tool_use"`) {
		t.Errorf("expected sse stream to contain stop_reason tool_use, got:\n%s", sseStr)
	}
}

// traeAutoDriveServer builds a fake Trae upstream that serves a scripted SSE
// body per incoming request, so auto-drive continuation can be asserted
// deterministically.
func traeAutoDriveServer(t *testing.T, scripts [][]string, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(atomic.AddInt32(hits, 1)) - 1
		if idx >= len(scripts) {
			idx = len(scripts) - 1
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		w.WriteHeader(http.StatusOK)
		for _, l := range scripts[idx] {
			_, _ = w.Write([]byte(l))
			flusher.Flush()
		}
	}))
}

func traeAutoDriveClaudeStream(t *testing.T, serverURL string) string {
	t.Helper()
	exec := NewTraeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		ID:       "test-trae-autodrive",
		Provider: "trae",
		Storage: &traeauth.TraeTokenStorage{
			AccessToken: "test-token",
			Host:        serverURL,
		},
	}
	claudePayload := []byte(`{
		"model": "glm-5.3-flash",
		"stream": true,
		"messages": [{"role": "user", "content": "排查一下这个问题"}],
		"tools": [
			{
				"name": "Bash",
				"description": "Run shell command",
				"input_schema": {"type": "object", "properties": {"command": {"type": "string"}}}
			}
		]
	}`)
	streamRes, err := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "glm-5.3-flash",
		Payload: claudePayload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("stream execute failed: %v", err)
	}
	var sb strings.Builder
	for c := range streamRes.Chunks {
		if c.Err != nil {
			t.Fatalf("unexpected stream err: %v", c.Err)
		}
		sb.Write(c.Payload)
	}
	return sb.String()
}

var (
	traeDeferralScript = []string{
		"event: output\n",
		`data: {"content":"` + "`apiCall` 没有导出，我直接写个临时脚本调 management 接口：" + `"}` + "\n\n",
		"event: done\n",
		`data: {"finish_reason":"stop"}` + "\n\n",
		"data: [DONE]\n\n",
	}
	traeToolCallScript = []string{
		"event: output\n",
		`data: {"content":"<toolcall>{\"name\": \"Bash\", \"params\": {\"command\": \"pwd\"}}</toolcall>"}` + "\n\n",
		"event: done\n",
		`data: {"finish_reason":"stop"}` + "\n\n",
		"data: [DONE]\n\n",
	}
	// Upstream accepts the retry but yields no content at all before done.
	traeEmptyScript = []string{
		"event: done\n",
		`data: {"finish_reason":"stop"}` + "\n\n",
		"data: [DONE]\n\n",
	}
	// Upstream deliberates but emits neither a reply nor a tool call. This is the
	// shape that used to stall the agent loop in production.
	traeReasoningOnlyScript = []string{
		"event: output\n",
		`data: {"reasoning":"用户希望我立刻调用下一个工具，让我想想该用哪个。"}` + "\n\n",
		"event: done\n",
		`data: {"finish_reason":"stop"}` + "\n\n",
		"data: [DONE]\n\n",
	}
)

// traeAutoDriveRecordingServer behaves like traeAutoDriveServer but also keeps
// every request body so the shape of the auto-drive continuation payload can be
// asserted.
func traeAutoDriveRecordingServer(t *testing.T, scripts [][]string, bodies *[][]byte, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*bodies = append(*bodies, body)
		idx := len(*bodies) - 1
		mu.Unlock()
		if idx >= len(scripts) {
			idx = len(scripts) - 1
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		w.WriteHeader(http.StatusOK)
		for _, l := range scripts[idx] {
			_, _ = w.Write([]byte(l))
			flusher.Flush()
		}
	}))
}

// A continuation that returns reasoning but no reply and no tool call is still a
// stalled turn, so it must keep being driven instead of falling through to
// end_turn — that fall-through is what showed up as a dead turn in Claude Code.
func TestTraeAutoDriveRecoversReasoningOnlyContinuation(t *testing.T) {
	var hits int32
	server := traeAutoDriveServer(t, [][]string{traeDeferralScript, traeReasoningOnlyScript, traeToolCallScript}, &hits)
	defer server.Close()

	sse := traeAutoDriveClaudeStream(t, server.URL)

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("expected 3 upstream requests (original + 2 auto-drives), got %d", got)
	}
	if !strings.Contains(sse, `"stop_reason":"tool_use"`) {
		t.Errorf("expected stop_reason tool_use after driving a reasoning-only turn, got:\n%s", sse)
	}
	if strings.Contains(sse, `"stop_reason":"end_turn"`) {
		t.Errorf("reasoning-only continuation must not end the turn, got:\n%s", sse)
	}
}

// Once a drive is under way the turn is already known to be stalled. A
// continuation that answers with ordinary prose and still no tool call must keep
// being driven, instead of being accepted as a finished turn just because the new
// text does not read like a deferral.
func TestTraeAutoDriveKeepsDrivingNonDeferralContinuation(t *testing.T) {
	var hits int32
	proseScript := []string{
		"event: output\n",
		`data: {"content":"好的，我明白了。"}` + "\n\n",
		"event: done\n",
		`data: {"finish_reason":"stop"}` + "\n\n",
		"data: [DONE]\n\n",
	}
	server := traeAutoDriveServer(t, [][]string{traeDeferralScript, proseScript, traeToolCallScript}, &hits)
	defer server.Close()

	sse := traeAutoDriveClaudeStream(t, server.URL)

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("expected 3 upstream requests (original + 2 auto-drives), got %d", got)
	}
	if !strings.Contains(sse, `"stop_reason":"tool_use"`) {
		t.Errorf("expected stop_reason tool_use after driving a non-deferral continuation, got:\n%s", sse)
	}
}

// Repeated drives must be rebuilt from the pre-drive payload: stacking each
// attempt on top of the previous one duplicates the action rule and leaves two
// user messages back to back, which degrades the continuation further.
func TestTraeAutoDriveDoesNotStackDrivePrompts(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies [][]byte
	)
	server := traeAutoDriveRecordingServer(t,
		[][]string{traeDeferralScript, traeReasoningOnlyScript, traeToolCallScript}, &bodies, &mu)
	defer server.Close()

	traeAutoDriveClaudeStream(t, server.URL)

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 {
		t.Fatalf("expected 3 upstream requests, got %d", len(bodies))
	}
	for i, body := range bodies[1:] {
		roles := gjson.GetBytes(body, "messages.#.role").Array()
		if len(roles) == 0 {
			t.Fatalf("drive %d: no messages in payload: %s", i+1, body)
		}
		for j := 1; j < len(roles); j++ {
			if roles[j].String() == "user" && roles[j-1].String() == "user" {
				t.Errorf("drive %d: consecutive user messages at index %d: %v", i+1, j, roles)
			}
		}
		// The standing "[Agent Action Rule / 行动硬约束" reminder is always injected;
		// only the drive prompt uses the 【...】 form, so count that one.
		if got := strings.Count(string(body), "【Agent Action Rule"); got != 1 {
			t.Errorf("drive %d: expected exactly 1 drive prompt in payload, got %d", i+1, got)
		}
	}
	// Each drive restarts from the same base, so the payloads stay the same length.
	if a, b := len(gjson.GetBytes(bodies[1], "messages").Array()), len(gjson.GetBytes(bodies[2], "messages").Array()); a != b {
		t.Errorf("drive payloads grew across attempts: %d then %d messages", a, b)
	}
}

// A transitional deferral must be auto-driven into a real tool call so that
// Claude Code keeps the agent loop running instead of returning to the user.
func TestTraeAutoDriveConvertsDeferralIntoToolUse(t *testing.T) {
	var hits int32
	server := traeAutoDriveServer(t, [][]string{traeDeferralScript, traeToolCallScript}, &hits)
	defer server.Close()

	sse := traeAutoDriveClaudeStream(t, server.URL)

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 upstream requests (original + auto-drive), got %d", got)
	}
	if !strings.Contains(sse, `"type":"tool_use"`) {
		t.Errorf("expected tool_use block after auto-drive, got:\n%s", sse)
	}
	if !strings.Contains(sse, `"stop_reason":"tool_use"`) {
		t.Errorf("expected stop_reason tool_use after auto-drive, got:\n%s", sse)
	}
	if strings.Contains(sse, `"stop_reason":"end_turn"`) {
		t.Errorf("auto-drive turn must not end with end_turn, got:\n%s", sse)
	}
}

// If the auto-drive retry comes back empty, the executor must drive again
// rather than silently falling through to end_turn.
func TestTraeAutoDriveRetriesWhenContinuationIsEmpty(t *testing.T) {
	var hits int32
	server := traeAutoDriveServer(t, [][]string{traeDeferralScript, traeEmptyScript, traeToolCallScript}, &hits)
	defer server.Close()

	sse := traeAutoDriveClaudeStream(t, server.URL)

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("expected 3 upstream requests (original + 2 auto-drives), got %d", got)
	}
	if !strings.Contains(sse, `"stop_reason":"tool_use"`) {
		t.Errorf("expected stop_reason tool_use after second auto-drive, got:\n%s", sse)
	}
}

// A continuation that fails in transport (proxy refused, non-2xx) must spend the
// remaining budget on another try. Falling through to end_turn on the first
// failure is what turned a one-second proxy blip into a dead turn.
func TestTraeAutoDriveRetriesWhenContinuationRequestFails(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(atomic.AddInt32(&hits, 1)) - 1
		if idx == 1 {
			http.Error(w, "proxy down", http.StatusBadGateway)
			return
		}
		script := traeDeferralScript
		if idx >= 2 {
			script = traeToolCallScript
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		w.WriteHeader(http.StatusOK)
		for _, l := range script {
			_, _ = w.Write([]byte(l))
			flusher.Flush()
		}
	}))
	defer server.Close()

	sse := traeAutoDriveClaudeStream(t, server.URL)

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("expected 3 upstream requests (deferral + failed drive + retry), got %d", got)
	}
	if !strings.Contains(sse, `"stop_reason":"tool_use"`) {
		t.Errorf("expected stop_reason tool_use after retrying a failed continuation, got:\n%s", sse)
	}
}

// An upstream turn that yields nothing at all must be driven too: Claude Code
// renders an empty end_turn response as a dead "No response requested." turn.
func TestTraeAutoDriveRecoversEmptyFirstTurn(t *testing.T) {
	var hits int32
	server := traeAutoDriveServer(t, [][]string{traeEmptyScript, traeToolCallScript}, &hits)
	defer server.Close()

	sse := traeAutoDriveClaudeStream(t, server.URL)

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 upstream requests (empty original + auto-drive), got %d", got)
	}
	if !strings.Contains(sse, `"stop_reason":"tool_use"`) {
		t.Errorf("expected stop_reason tool_use after driving an empty turn, got:\n%s", sse)
	}
}
