package helps

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	traeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/trae"
	"github.com/tidwall/gjson"
)

const (
	TraeAppIDCN            = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
	TraeDefaultVersionCN   = "3.3.99"
	TraeDefaultVersionSG   = "3.5.51"
	TraeDefaultVersionCode = "20260901"
)

// ModelPrefersRawChat returns whether the requested model should preferably be routed via llm_raw_chat.
func ModelPrefersRawChat(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	switch m {
	case "kimi-k3", "kimi-k2.8-preview", "kimi-k2.8", "deepseek-v4.1-flash", "glm-5.3", "glm-5.3-flash", "deepseek-v4-flash-official", "qwen3.8-max", "qwen-3.8-max":
		return true
	}
	return false
}

// ResolveTraeModel maps user-facing model names or aliases to Trae function and config_name.
func ResolveTraeModel(model string) (functionName string, configName string) {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" || m == "auto" || m == "trae-auto" || m == "inline_chat" {
		return "inline_chat", ""
	}

	// Exact matches / direct configs
	switch m {
	case "kimi-k3":
		return "solo_agent", "kimi-k3"
	case "kimi-k2.8-preview", "kimi-k2.8":
		return "solo_agent", "kimi-k2.8-preview"
	case "deepseek-v4.1-flash":
		return "solo_agent", "DeepSeek-V4.1-Flash"
	case "glm-5.3":
		return "solo_agent", "glm-5.3"
	case "glm-5.3-flash":
		return "solo_agent", "glm-5.3-flash"
	case "deepseek-v4-pro-official":
		return "solo_agent", "DeepSeek-V4-Pro-Official"
	case "deepseek-v4-flash-official":
		return "solo_agent", "DeepSeek-V4-Flash-Official"
	case "qwen3.8-max", "qwen-3.8-max":
		return "solo_agent", "qwen3.8-max"
	case "doubao-seed-evolving":
		return "chat_v3", "Doubao-Seed-Evolving"
	case "glm-5.2":
		return "chat_v3", "glm-5.2"
	case "glm-5.1":
		return "chat_v3", "glm-5.1"
	case "glm-5":
		return "chat_v3", "glm-5"
	case "glm-5v-turbo":
		return "chat_v3", "glm-5v-turbo"
	case "glm-4.7":
		return "chat_v3", "glm-4.7"
	case "glm-4.6":
		return "chat_v3", "glm-4.6"
	case "doubao-seed-code", "doubao-1-6", "doubao_1_6":
		return "chat_v3", "Doubao_1_6"
	case "doubao-seed-2.0-code":
		return "chat_v3", "Doubao-Seed-2.0-Code"
	case "doubao-1.8", "doubao_1_8":
		return "chat_v3", "doubao_1_8"
	case "doubao-seed-2-1-pro":
		return "chat_v3", "Doubao-Seed-2.1-Pro"
	case "doubao-seed-2-1-turbo":
		return "chat_v3", "Doubao-Seed-2.1-Turbo"
	case "deepseek-v4-pro", "deepseek-v3", "deepseek-chat":
		return "chat_v3", "deepseek-V4-Pro"
	case "deepseek-v4-flash":
		return "chat_v3", "DeepSeek-V4-Flash"
	case "deepseek-r1", "deepseek-reasoner":
		return "chat_v3", "custom_model_deepseek_reasoner"
	case "deepseek-v3-1", "deepseek-v3.1":
		return "chat_v3", "deepseek-V3.1"
	case "qwen-3.7-plus", "qwen3.7-plus":
		return "chat_v3", "qwen-3.7-plus"
	case "qwen-3.6-plus", "qwen3.6-plus":
		return "chat_v3", "qwen-3.6-plus"
	case "qwen-3.5", "qwen-3-5", "qwen3.5":
		return "chat_v3", "qwen-3.5"
	case "qwen3-coder", "qwen-3-coder":
		return "chat_v3", "qwen3-coder"
	case "kimi-k2.6":
		return "chat_v3", "kimi-k2.6"
	case "kimi-k2.5", "kimi-k2-5":
		return "chat_v3", "kimi-k2.5"
	case "kimi-k2":
		return "chat_v3", "kimi-k2"
	case "kimi-k2-7-code", "kimi-k2.7-code":
		return "chat_v3", "kimi-k2.7-code"
	case "minimax-m3":
		return "chat_v3", "minimax-m3"
	case "minimax-m2.7":
		return "chat_v3", "minimax-m2.7"
	case "minimax-m2.1":
		return "chat_v3", "minimax-m2.1"
	case "minimax-m2":
		return "chat_v3", "minimax-m2"
	}

	// Aliases
	if strings.HasPrefix(m, "claude-opus") || strings.HasPrefix(m, "claude-sonnet") ||
		strings.Contains(m, "3-7-sonnet") || strings.Contains(m, "3.7-sonnet") ||
		strings.Contains(m, "3-5-sonnet") || strings.Contains(m, "3.5-sonnet") {
		return "chat_v3", "glm-5.2"
	}
	if strings.HasPrefix(m, "claude-haiku") || strings.Contains(m, "3-5-haiku") || strings.Contains(m, "3.5-haiku") {
		return "chat_v3", "glm-5.1"
	}
	if strings.HasPrefix(m, "gpt-4o") || strings.HasPrefix(m, "gpt-5") {
		return "chat_v3", "custom_model_gpt-5"
	}
	if strings.Contains(m, "gemini-2.5-pro") {
		return "chat_v3", "custom_model_vercel_gemini"
	}
	if strings.Contains(m, "gemini-2.0-flash") || strings.Contains(m, "gemini-flash") {
		return "chat_v3", "custom_model_gemini"
	}

	return "chat_v3", model
}

func generateTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ApplyTraeHeaders populates Trae IDE specific headers on the outgoing HTTP request.
func ApplyTraeHeaders(req *http.Request, storage *traeauth.TraeTokenStorage, isStream bool) {
	if req == nil || storage == nil {
		return
	}

	token := strings.TrimSpace(storage.AccessToken)
	if token != "" {
		req.Header.Set("Authorization", "Cloud-IDE-JWT "+token)
		req.Header.Set("X-Cloudide-Token", token)
		req.Header.Set("x-ide-token", token)
	}

	req.Header.Set("Content-Type", "application/json")
	if isStream {
		req.Header.Set("Accept", "text/event-stream")
	}

	req.Header.Set("x-app-id", TraeAppIDCN)
	req.Header.Set("x-app-version", "default")
	versionCode := traeauth.DetectIdeVersionCode()
	req.Header.Set("x-ide-version-code", versionCode)
	req.Header.Set("x-app-version-code", versionCode)
	req.Header.Set("x-plugin-channel", "icube-ai")
	req.Header.Set("x-custom-trace-id", generateTraceID())

	reqID := uuid.New().String()
	req.Header.Set("X-Request-ID", reqID)
	req.Header.Set("X-Trae-Request-ID", reqID)

	brand := "82RF"
	cpu := "Intel"
	osType := runtime.GOOS
	if osType == "darwin" {
		brand = "MacBookPro"
		if runtime.GOARCH == "arm64" {
			cpu = "Apple"
		}
	}
	req.Header.Set("x-device-brand", brand)
	req.Header.Set("x-device-cpu", cpu)
	req.Header.Set("x-device-type", osType)
	req.Header.Set("x-os-version", fmt.Sprintf("%s %s", osType, runtime.GOARCH))

	machineID := storage.MachineID
	if machineID == "" {
		machineID = "00000000-0000-0000-0000-000000000000"
	}
	req.Header.Set("x-machine-id", machineID)

	deviceID := storage.DeviceID
	if deviceID == "" {
		deviceID = traeauth.HashDeviceID(machineID)
	}
	req.Header.Set("x-device-id", deviceID)

	ideVersion := traeauth.DetectIdeVersion(storage.Edition)
	req.Header.Set("x-ide-version", ideVersion)
	req.Header.Set("x-ide-version-type", "stable")
	req.Header.Set("request-traffic-type", "prod")

	if storage.UserID != "" {
		req.Header.Set("x-uid", storage.UserID)
	}
}

// BuildTraeRequestBody formats an incoming OpenAI chat completion payload into Trae llm_utils_chat format.
func BuildTraeRequestBody(rawPayload []byte, requestedModel string, storage *traeauth.TraeTokenStorage, stream bool) ([]byte, string, error) {
	root := gjson.ParseBytes(rawPayload)
	funcName, configName := ResolveTraeModel(requestedModel)

	outMap := make(map[string]any)
	outMap["function"] = funcName
	outMap["stream"] = stream
	outMap["session_id"] = "sess_" + strings.ReplaceAll(uuid.New().String(), "-", "")

	if storage != nil {
		if storage.UserID != "" {
			outMap["user_id"] = storage.UserID
		}
		deviceID := storage.DeviceID
		if deviceID == "" && storage.MachineID != "" {
			deviceID = traeauth.HashDeviceID(storage.MachineID)
		}
		if deviceID != "" {
			outMap["device_id"] = deviceID
		}
	}

	if funcName != "inline_chat" && configName != "" {
		outMap["config_name"] = configName
		outMap["model"] = configName
	}

	// Format messages
	rawMessages := root.Get("messages")
	if rawMessages.Exists() && rawMessages.IsArray() {
		var msgs []map[string]any
		for _, m := range rawMessages.Array() {
			role := m.Get("role").String()
			contentVal := m.Get("content")
			var contentBlocks []map[string]any

			if contentVal.IsArray() {
				for _, block := range contentVal.Array() {
					if block.IsObject() {
						t := block.Get("type").String()
						if t == "text" {
							contentBlocks = append(contentBlocks, map[string]any{
								"type": "text",
								"text": block.Get("text").String(),
							})
						} else {
							// pass through other blocks
							contentBlocks = append(contentBlocks, block.Value().(map[string]any))
						}
					} else {
						contentBlocks = append(contentBlocks, map[string]any{
							"type": "text",
							"text": block.String(),
						})
					}
				}
			} else {
				contentBlocks = append(contentBlocks, map[string]any{
					"type": "text",
					"text": contentVal.String(),
				})
			}

			msgs = append(msgs, map[string]any{
				"role":    role,
				"content": contentBlocks,
			})
		}
		outMap["messages"] = msgs
	}

	if maxTokens := root.Get("max_tokens"); maxTokens.Exists() {
		outMap["max_tokens"] = maxTokens.Int()
	} else if maxCompTokens := root.Get("max_completion_tokens"); maxCompTokens.Exists() {
		outMap["max_tokens"] = maxCompTokens.Int()
	}

	if temp := root.Get("temperature"); temp.Exists() {
		outMap["temperature"] = temp.Float()
	}
	if topP := root.Get("top_p"); topP.Exists() {
		outMap["top_p"] = topP.Float()
	}
	if pres := root.Get("presence_penalty"); pres.Exists() {
		outMap["presence_penalty"] = pres.Float()
	}
	if freq := root.Get("frequency_penalty"); freq.Exists() {
		outMap["frequency_penalty"] = freq.Float()
	}
	if stop := root.Get("stop"); stop.Exists() {
		outMap["stop"] = stop.Value()
	}

	res, err := json.Marshal(outMap)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal trae request body: %w", err)
	}
	return res, configName, nil
}

// BuildTraeRawChatRequestBody formats an incoming OpenAI chat completion payload into Trae /api/ide/v2/llm_raw_chat format.
func BuildTraeRawChatRequestBody(rawPayload []byte, requestedModel string, storage *traeauth.TraeTokenStorage, stream bool) ([]byte, string, error) {
	root := gjson.ParseBytes(rawPayload)
	funcName, configName := ResolveTraeModel(requestedModel)
	if funcName == "" || funcName == "chat_v3" {
		funcName = "solo_agent"
	}
	if configName == "" {
		configName = requestedModel
	}

	outMap := make(map[string]any)
	outMap["function"] = funcName
	outMap["raw_chat_function"] = funcName
	outMap["stream"] = stream
	outMap["session_id"] = "sess_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	outMap["config_name"] = configName
	outMap["model_name"] = configName + "__dev"

	if storage != nil {
		if storage.UserID != "" {
			outMap["user_id"] = storage.UserID
		}
		deviceID := storage.DeviceID
		if deviceID == "" && storage.MachineID != "" {
			deviceID = traeauth.HashDeviceID(storage.MachineID)
		}
		if deviceID != "" {
			outMap["device_id"] = deviceID
		}
	}

	// Format messages
	rawMessages := root.Get("messages")
	if rawMessages.Exists() && rawMessages.IsArray() {
		var msgs []map[string]any
		for _, m := range rawMessages.Array() {
			role := m.Get("role").String()
			contentVal := m.Get("content")
			var contentBlocks []map[string]any

			if contentVal.IsArray() {
				for _, block := range contentVal.Array() {
					if block.IsObject() {
						t := block.Get("type").String()
						if t == "text" {
							contentBlocks = append(contentBlocks, map[string]any{
								"type": "text",
								"text": block.Get("text").String(),
							})
						} else {
							contentBlocks = append(contentBlocks, block.Value().(map[string]any))
						}
					} else {
						contentBlocks = append(contentBlocks, map[string]any{
							"type": "text",
							"text": block.String(),
						})
					}
				}
			} else {
				contentBlocks = append(contentBlocks, map[string]any{
					"type": "text",
					"text": contentVal.String(),
				})
			}

			msgs = append(msgs, map[string]any{
				"role":    role,
				"content": contentBlocks,
			})
		}
		outMap["messages"] = msgs
	}

	if maxTokens := root.Get("max_tokens"); maxTokens.Exists() {
		outMap["max_tokens"] = maxTokens.Int()
	} else if maxCompTokens := root.Get("max_completion_tokens"); maxCompTokens.Exists() {
		outMap["max_tokens"] = maxCompTokens.Int()
	}

	if temp := root.Get("temperature"); temp.Exists() {
		outMap["temperature"] = temp.Float()
	}
	if topP := root.Get("top_p"); topP.Exists() {
		outMap["top_p"] = topP.Float()
	}

	res, err := json.Marshal(outMap)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal trae raw chat request body: %w", err)
	}
	return res, configName, nil
}

type TraeTokenUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
	ReasoningTokens  int64 `json:"reasoning_tokens,omitempty"`
}

type TraeParsedChunk struct {
	Type         string          // "event_name", "text", "token_usage", "done", "error"
	Content      string          // text content delta
	Reasoning    string          // reasoning content delta
	FinishReason string          // "stop", "length", etc.
	TokenUsage   *TraeTokenUsage // token usage info
	ErrorCode    int             // upstream error code
	ErrorMessage string          // upstream error message
}

// ParseTraeSSELine parses a single SSE line and updates currentEvent.
func ParseTraeSSELine(line string, currentEvent *string) *TraeParsedChunk {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil
	}

	if strings.HasPrefix(trimmed, "event:") {
		ev := strings.TrimSpace(trimmed[6:])
		if currentEvent != nil {
			*currentEvent = ev
		}
		return &TraeParsedChunk{Type: "event_name"}
	}

	if strings.HasPrefix(trimmed, "data:") {
		dataStr := strings.TrimSpace(trimmed[5:])
		if dataStr == "[DONE]" {
			return &TraeParsedChunk{
				Type:         "done",
				FinishReason: "stop",
			}
		}

		ev := ""
		if currentEvent != nil {
			ev = *currentEvent
		}

		res := gjson.Parse(dataStr)
		if !res.IsObject() {
			return nil
		}

		switch ev {
		case "output":
			chunk := &TraeParsedChunk{Type: "text"}
			// Support new generation (content/reasoning) & old generation (response/reasoning_content)
			if c := res.Get("content"); c.Exists() && c.String() != "" {
				chunk.Content = c.String()
			} else if r := res.Get("response"); r.Exists() && r.String() != "" {
				// Filter out internal building prompt logs
				str := r.String()
				if !strings.HasPrefix(str, "Building prompt:") && !strings.HasPrefix(str, "Completed building prompt") {
					chunk.Content = str
				}
			}

			if re := res.Get("reasoning"); re.Exists() && re.String() != "" {
				chunk.Reasoning = re.String()
			} else if rc := res.Get("reasoning_content"); rc.Exists() && rc.String() != "" {
				chunk.Reasoning = rc.String()
			}

			if chunk.Content != "" || chunk.Reasoning != "" {
				return chunk
			}
			return nil

		case "token_usage":
			usage := &TraeTokenUsage{
				PromptTokens:     res.Get("prompt_tokens").Int(),
				CompletionTokens: res.Get("completion_tokens").Int(),
				TotalTokens:      res.Get("total_tokens").Int(),
				ReasoningTokens:  res.Get("reasoning_tokens").Int(),
			}
			return &TraeParsedChunk{
				Type:       "token_usage",
				TokenUsage: usage,
			}

		case "done":
			fr := res.Get("finish_reason").String()
			if fr == "" {
				fr = "stop"
			}
			return &TraeParsedChunk{
				Type:         "done",
				FinishReason: fr,
			}

		case "error":
			code := int(res.Get("code").Int())
			msg := res.Get("message").String()
			if msg == "" {
				msg = res.Get("msg").String()
			}
			return &TraeParsedChunk{
				Type:         "error",
				ErrorCode:    code,
				ErrorMessage: msg,
			}
		}
	}

	return nil
}

// FormatOpenAIStreamChunk constructs an SSE chunk in OpenAI format.
func FormatOpenAIStreamChunk(id, model, content, reasoning, finishReason string) []byte {
	choice := map[string]any{
		"index": 0,
	}

	if finishReason != "" {
		choice["delta"] = map[string]any{}
		choice["finish_reason"] = finishReason
	} else {
		delta := make(map[string]any)
		if content != "" {
			delta["content"] = content
		}
		if reasoning != "" {
			delta["reasoning_content"] = reasoning
		}
		choice["delta"] = delta
		choice["finish_reason"] = nil
	}

	chunkObj := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []any{choice},
	}

	b, _ := json.Marshal(chunkObj)
	return b
}

// FormatOpenAINonStreamResponse constructs a non-streaming chat completion JSON response in OpenAI format.
func FormatOpenAINonStreamResponse(id, model, fullContent, fullReasoning string, usage *TraeTokenUsage) []byte {
	msg := map[string]any{
		"role":    "assistant",
		"content": fullContent,
	}
	if fullReasoning != "" {
		msg["reasoning_content"] = fullReasoning
	}

	choice := map[string]any{
		"index":         0,
		"message":       msg,
		"finish_reason": "stop",
	}

	respObj := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []any{choice},
	}

	if usage != nil {
		uObj := map[string]any{
			"prompt_tokens":     usage.PromptTokens,
			"completion_tokens": usage.CompletionTokens,
			"total_tokens":      usage.TotalTokens,
		}
		if usage.ReasoningTokens > 0 {
			uObj["completion_tokens_details"] = map[string]any{
				"reasoning_tokens": usage.ReasoningTokens,
			}
		}
		respObj["usage"] = uObj
	}

	b, _ := json.Marshal(respObj)
	return b
}
