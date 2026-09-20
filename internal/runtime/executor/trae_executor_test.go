package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	traeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/trae"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
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
		{"glm-5.2", "chat_v3", "glm-5.2"},
		{"glm-5.1", "chat_v3", "glm-5.1"},
		{"glm-5", "chat_v3", "glm-5"},
		{"doubao-seed-code", "chat_v3", "Doubao_1_6"},
		{"doubao-1-6", "chat_v3", "Doubao_1_6"},
		{"DeepSeek-V4-Pro", "chat_v3", "DeepSeek-V4-Pro"},
		{"deepseek-r1", "chat_v3", "custom_model_deepseek_reasoner"},
		{"qwen-3.7-plus", "chat_v3", "qwen-3.7-plus"},
		{"kimi-k2.6", "chat_v3", "kimi-k2.6"},
		{"claude-3-7-sonnet", "chat_v3", "glm-5.2"},
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
	if parsed.Get("function").String() != "chat_v3" {
		t.Errorf("expected function chat_v3, got %q", parsed.Get("function").String())
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
