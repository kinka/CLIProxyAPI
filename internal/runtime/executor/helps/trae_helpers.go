package helps

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
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
	fn, _ := ResolveTraeModel(model)
	return fn == "solo_agent"
}

// ResolveTraeModel maps user-facing model names or aliases to Trae function and config_name.
func ResolveTraeModel(model string) (functionName string, configName string) {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" || m == "auto" || m == "trae-auto" || m == "inline_chat" {
		return "inline_chat", ""
	}

	// Exact matches / direct configs
	switch m {
	// Kimi series
	case "kimi-k3", "k3":
		return "solo_agent", "kimi-k3"
	case "kimi-k2.8-preview", "kimi-k2.8", "k2.8":
		return "solo_agent", "kimi-k2.8-preview"
	case "kimi-k2.6", "k2.6":
		return "solo_agent", "kimi-k2.6"
	case "kimi-k2.7-code", "kimi-k2-7-code", "k2.7-code":
		return "solo_agent", "kimi-k2.7-code"
	case "kimi-k2.5", "kimi-k2-5":
		return "chat_v3", "kimi-k2.5"
	case "kimi-k2":
		return "chat_v3", "kimi-k2"

	// DeepSeek series
	case "deepseek-v4.1-flash", "deepseek-v4-flash", "deepseek-flash", "dsf":
		return "solo_agent", "DeepSeek-V4.1-Flash"
	case "deepseek-v4-flash-official":
		return "solo_agent", "DeepSeek-V4-Flash-Official"
	case "deepseek-v4-pro-official", "deepseek-v4-pro", "dsp", "deepseek-pro":
		return "solo_agent", "DeepSeek-V4-Pro-Official"
	case "deepseek-v3", "deepseek-chat":
		return "solo_agent", "DeepSeek-V4-Pro"
	case "deepseek-r1", "deepseek-reasoner":
		return "chat_v3", "custom_model_deepseek_reasoner"
	case "deepseek-v3-1", "deepseek-v3.1":
		return "chat_v3", "deepseek-V3.1"

	// GLM series
	case "glm-5.3-flash", "gf":
		return "solo_agent", "glm-5.3-flash"
	case "glm-5.3":
		return "solo_agent", "glm-5.3"
	case "glm-5.2":
		return "solo_agent", "glm-5.2"
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

	// Qwen series
	case "qwen3.8-max", "qwen-3.8-max":
		return "solo_agent", "qwen3.8-max"
	case "qwen-3.7-plus", "qwen3.7-plus", "qwen-plus", "qwen":
		return "solo_agent", "qwen-3.7-plus"
	case "qwen-3.6-plus", "qwen3.6-plus":
		return "solo_agent", "qwen-3.6-plus"
	case "qwen-3.5", "qwen-3-5", "qwen3.5":
		return "chat_v3", "qwen-3.5"
	case "qwen3-coder", "qwen-3-coder":
		return "chat_v3", "qwen3-coder"

	// Doubao series
	case "doubao-seed-code", "doubao-1-6", "doubao_1_6", "doubao":
		return "solo_agent", "Doubao_1_6"
	case "doubao-seed-2.0-code":
		return "solo_agent", "Doubao-Seed-2.0-Code"
	case "doubao-seed-evolving":
		return "solo_agent", "Doubao-Seed-Evolving"
	case "doubao-1.8", "doubao_1_8":
		return "chat_v3", "doubao_1_8"
	case "doubao-seed-2-1-pro":
		return "chat_v3", "Doubao-Seed-2.1-Pro"
	case "doubao-seed-2-1-turbo":
		return "chat_v3", "Doubao-Seed-2.1-Turbo"

	// MiniMax series
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
		return "solo_agent", "glm-5.3-flash"
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

// TraeToolDefinition represents a tool available to the model.
type TraeToolDefinition struct {
	Name        string
	Description string
	Parameters  []string
}

// BuildToolMap builds a lookup table mapping lowercase and common aliases to original tool names.
func BuildToolMap(tools []TraeToolDefinition) map[string]string {
	m := make(map[string]string)
	for _, t := range tools {
		if t.Name == "" {
			continue
		}
		lower := strings.ToLower(t.Name)
		clean := strings.ReplaceAll(lower, "_", "")
		m[lower] = t.Name
		m[clean] = t.Name
		m[t.Name] = t.Name

		switch clean {
		case "bash", "executecommand", "runcommand":
			m["bash"] = t.Name
			m["execute_command"] = t.Name
			m["run_command"] = t.Name
		case "read", "readfile":
			m["read"] = t.Name
			m["read_file"] = t.Name
			m["readfile"] = t.Name
		case "write", "writefile":
			m["write"] = t.Name
			m["write_file"] = t.Name
			m["writefile"] = t.Name
		case "edit", "editfile":
			m["edit"] = t.Name
			m["edit_file"] = t.Name
			m["editfile"] = t.Name
		case "multiedit":
			m["multiedit"] = t.Name
			m["multi_edit"] = t.Name
		case "glob", "listdir", "listfiles":
			m["glob"] = t.Name
			m["listdir"] = t.Name
			m["list_files"] = t.Name
		case "grep", "searchfiles":
			m["grep"] = t.Name
			m["search_files"] = t.Name
		case "webfetch", "fetchurl":
			m["webfetch"] = t.Name
			m["fetch_url"] = t.Name
			m["web_fetch"] = t.Name
		case "websearch", "searchinternet":
			m["websearch"] = t.Name
			m["search_internet"] = t.Name
			m["web_search"] = t.Name
		}
	}
	return m
}

// ExtractToolMapFromPayload parses tool declarations from an incoming JSON payload and builds a tool mapping.
func ExtractToolMapFromPayload(rawPayload []byte, fallbackPayload []byte) map[string]string {
	root := gjson.ParseBytes(rawPayload)
	toolsResult := root.Get("tools")
	if (!toolsResult.Exists() || !toolsResult.IsArray() || len(toolsResult.Array()) == 0) && len(fallbackPayload) > 0 {
		fbRoot := gjson.ParseBytes(fallbackPayload)
		if fbTools := fbRoot.Get("tools"); fbTools.Exists() && fbTools.IsArray() {
			toolsResult = fbTools
		}
	}

	if !toolsResult.Exists() || !toolsResult.IsArray() {
		return make(map[string]string)
	}

	var toolDefs []TraeToolDefinition
	for _, t := range toolsResult.Array() {
		name := t.Get("function.name").String()
		if name == "" {
			name = t.Get("name").String()
		}
		if name == "" {
			continue
		}
		desc := t.Get("function.description").String()
		if desc == "" {
			desc = t.Get("description").String()
		}
		if len(desc) > 200 {
			desc = desc[:200]
		}

		var paramNames []string
		props := t.Get("function.parameters.properties")
		if !props.Exists() {
			props = t.Get("input_schema.properties")
		}
		if props.Exists() && props.IsObject() {
			props.ForEach(func(key, _ gjson.Result) bool {
				paramNames = append(paramNames, key.String())
				return true
			})
		}

		toolDefs = append(toolDefs, TraeToolDefinition{
			Name:        name,
			Description: desc,
			Parameters:  paramNames,
		})
	}

	return BuildToolMap(toolDefs)
}

// FormatTraeMessagesWithTools extracts messages from OpenAI payload, handles tool results / tool calls,
// and injects tool system prompts to bridge agent execution.
func FormatTraeMessagesWithTools(root gjson.Result) ([]map[string]any, map[string]string) {
	rawMessages := root.Get("messages")
	if !rawMessages.Exists() || !rawMessages.IsArray() {
		return nil, nil
	}

	toolsResult := root.Get("tools")
	var toolDefs []TraeToolDefinition
	if toolsResult.Exists() && toolsResult.IsArray() {
		for _, t := range toolsResult.Array() {
			name := t.Get("function.name").String()
			if name == "" {
				name = t.Get("name").String()
			}
			if name == "" {
				continue
			}
			desc := t.Get("function.description").String()
			if desc == "" {
				desc = t.Get("description").String()
			}
			if len(desc) > 200 {
				desc = desc[:200]
			}

			var paramNames []string
			props := t.Get("function.parameters.properties")
			if !props.Exists() {
				props = t.Get("input_schema.properties")
			}
			if props.Exists() && props.IsObject() {
				props.ForEach(func(key, _ gjson.Result) bool {
					paramNames = append(paramNames, key.String())
					return true
				})
			}

			toolDefs = append(toolDefs, TraeToolDefinition{
				Name:        name,
				Description: desc,
				Parameters:  paramNames,
			})
		}
	}
	toolMap := BuildToolMap(toolDefs)

	// Detect if this is a tool continuation turn (tool results sent back)
	isToolContinuation := false
	callIDToName := make(map[string]string)
	for _, m := range rawMessages.Array() {
		role := m.Get("role").String()
		if role == "tool" || m.Get("tool_call_id").Exists() {
			isToolContinuation = true
		}
		if role == "assistant" && m.Get("tool_calls").Exists() {
			isToolContinuation = true
			for _, tc := range m.Get("tool_calls").Array() {
				tcID := tc.Get("id").String()
				tcName := tc.Get("function.name").String()
				if tcName == "" {
					tcName = tc.Get("name").String()
				}
				if tcID != "" && tcName != "" {
					callIDToName[tcID] = tcName
				}
			}
		}
		cStr := m.Get("content").String()
		if strings.Contains(cStr, "<tool_result") || strings.Contains(cStr, "tool_result") {
			isToolContinuation = true
		}
	}

	var msgs []map[string]any
	systemMsgIndex := -1

	for _, m := range rawMessages.Array() {
		role := m.Get("role").String()
		contentVal := m.Get("content")
		var contentBlocks []map[string]any

		if role == "tool" {
			// Convert OpenAI role="tool" to role="user" with <tool_result> tag
			callID := m.Get("tool_call_id").String()
			forName := callID
			if mapped, ok := callIDToName[callID]; ok && mapped != "" {
				forName = mapped
			}
			resultText := contentVal.String()
			wrapped := fmt.Sprintf("<tool_result for=\"%s\">\n%s\n</tool_result>", forName, resultText)
			msgs = append(msgs, map[string]any{
				"role": "user",
				"content": []map[string]any{
					{"type": "text", "text": wrapped},
				},
			})
			continue
		}

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
			textStr := contentVal.String()
			if textStr != "" || role != "assistant" {
				contentBlocks = append(contentBlocks, map[string]any{
					"type": "text",
					"text": textStr,
				})
			}
		}

		// If assistant message had tool_calls, ensure they are represented in <toolcall> format in content
		if role == "assistant" {
			toolCalls := m.Get("tool_calls")
			if toolCalls.Exists() && toolCalls.IsArray() {
				var tcTags strings.Builder
				for _, tc := range toolCalls.Array() {
					tcName := tc.Get("function.name").String()
					if tcName == "" {
						tcName = tc.Get("name").String()
					}
					tcArgs := tc.Get("function.arguments").String()
					if tcArgs == "" {
						tcArgs = tc.Get("arguments").String()
					}
					if tcArgs == "" {
						tcArgs = "{}"
					}
					var paramsObj any
					if err := json.Unmarshal([]byte(tcArgs), &paramsObj); err != nil {
						paramsObj = tcArgs
					}
					tcPayload, _ := json.Marshal(map[string]any{
						"name":   tcName,
						"params": paramsObj,
					})
					tcTags.WriteString(fmt.Sprintf("\n<toolcall>%s</toolcall>", string(tcPayload)))
				}
				if tcTags.Len() > 0 {
					contentBlocks = append(contentBlocks, map[string]any{
						"type": "text",
						"text": tcTags.String(),
					})
				}
			}
		}

		if len(contentBlocks) > 0 {
			var merged []map[string]any
			var curText strings.Builder
			for _, b := range contentBlocks {
				if b["type"] == "text" {
					if t, ok := b["text"].(string); ok {
						curText.WriteString(t)
					}
				} else {
					if curText.Len() > 0 {
						merged = append(merged, map[string]any{
							"type": "text",
							"text": curText.String(),
						})
						curText.Reset()
					}
					merged = append(merged, b)
				}
			}
			if curText.Len() > 0 {
				merged = append(merged, map[string]any{
					"type": "text",
					"text": curText.String(),
				})
			}
			contentBlocks = merged
		}

		if role == "system" && systemMsgIndex == -1 {
			systemMsgIndex = len(msgs)
		}

		msgs = append(msgs, map[string]any{
			"role":    role,
			"content": contentBlocks,
		})
	}

	// Build tool system prompt
	var toolSystemMsg string
	if len(toolDefs) > 0 {
		var sb strings.Builder
		sb.WriteString("\n\n<available_tools>\n")
		sb.WriteString("You have access to the following tools. To call a tool, output a toolcall block in JSON format:\n")
		sb.WriteString("<toolcall>{\"name\": \"ToolName\", \"params\": {\"param1\": \"value1\"}}</toolcall>\n\n")
		sb.WriteString("CRITICAL AGENT RULES:\n")
		sb.WriteString("- When you need to inspect files, execute commands, or gather workspace information, you MUST call the appropriate tool immediately in your response.\n")
		sb.WriteString("- DO NOT merely state what you will do (e.g. avoid saying 'I will check...', 'Let me run...', '我来查看' without calling the tool). You MUST emit the <toolcall> block directly.\n")
		sb.WriteString("- The <toolcall> block MUST contain valid JSON with \"name\" and \"params\" keys\n")
		sb.WriteString("- Do NOT use XML attributes like: ToolName param=\"value\"\n")
		sb.WriteString("- Do NOT use <arg_key>/<arg_value> tags\n")
		sb.WriteString("- Use the EXACT tool names listed below (case-sensitive)\n")
		sb.WriteString("- Output the <toolcall> block directly in your response, not inside other tags\n\n")
		sb.WriteString("Available tools:\n")
		for _, td := range toolDefs {
			paramsStr := strings.Join(td.Parameters, ", ")
			sb.WriteString(fmt.Sprintf("- %s(%s): %s\n", td.Name, paramsStr, td.Description))
		}
		if isToolContinuation {
			sb.WriteString("\nCRITICAL: You are in a multi-turn tool use conversation. The user has sent back tool results from your previous tool calls. You MUST:\n")
			sb.WriteString("1. Analyze the tool results carefully\n")
			sb.WriteString("2. If you need more information, call another tool using <toolcall> format\n")
			sb.WriteString("3. If you have enough information to answer the user's question, provide your final answer as text\n")
			sb.WriteString("4. Do NOT just say \"I've completed the task\" without providing the actual information or result the user requested\n")
			sb.WriteString("5. Do NOT stop prematurely - continue working until the task is fully complete\n")
		}
		sb.WriteString("</available_tools>")
		toolSystemMsg = sb.String()
	} else if isToolContinuation {
		toolSystemMsg = "\n\nIMPORTANT: You are in a multi-turn tool use conversation. The user has sent back tool results. You MUST analyze the results and continue working. If you need more information, call another tool. Otherwise, provide a complete answer. Do NOT stop prematurely."
	}

	// Inject tool system prompt
	if toolSystemMsg != "" {
		if systemMsgIndex >= 0 && systemMsgIndex < len(msgs) {
			sysBlocks, ok := msgs[systemMsgIndex]["content"].([]map[string]any)
			if ok && len(sysBlocks) > 0 {
				if lastText, hasText := sysBlocks[len(sysBlocks)-1]["text"].(string); hasText {
					sysBlocks[len(sysBlocks)-1]["text"] = lastText + toolSystemMsg
				} else {
					sysBlocks = append(sysBlocks, map[string]any{
						"type": "text",
						"text": toolSystemMsg,
					})
				}
				msgs[systemMsgIndex]["content"] = sysBlocks
			} else {
				msgs[systemMsgIndex]["content"] = []map[string]any{
					{"type": "text", "text": toolSystemMsg},
				}
			}
		} else {
			msgs = append([]map[string]any{{
				"role": "system",
				"content": []map[string]any{
					{"type": "text", "text": toolSystemMsg},
				},
			}}, msgs...)
		}
	}

	// Inject an active tool-use reminder at the end of the final user message.
	// In long conversations or interactive multi-turn sessions (e.g. Claude Code), models tend to defer
	// with conversational polite phrases (like "好的，稍等我来查") unless actively reminded at the turn boundary.
	if len(toolDefs) > 0 && len(msgs) > 0 {
		lastIdx := len(msgs) - 1
		if msgs[lastIdx]["role"] == "user" {
			if uBlocks, ok := msgs[lastIdx]["content"].([]map[string]any); ok && len(uBlocks) > 0 {
				lastBlockText, _ := uBlocks[len(uBlocks)-1]["text"].(string)
				var reminder string
				if strings.Contains(lastBlockText, "<tool_result") {
					reminder = "\n\n[Agent Continuation Rule: Analyze the tool result above. If the task is not yet finished, call the next tool immediately using <toolcall>. DO NOT pause or say you will do it without the toolcall. If completely finished, provide your final response as text.]"
				} else {
					reminder = "\n\n[Agent Action Rule: You have access to tools. If you need to search, execute commands, or inspect workspace/files to answer, call the appropriate tool immediately using <toolcall> block. DO NOT merely say you will do it (e.g. avoid '好的我来查', 'I will check') without emitting the <toolcall>.]"
				}
				uBlocks[len(uBlocks)-1]["text"] = lastBlockText + reminder
				msgs[lastIdx]["content"] = uBlocks
			}
		}
	}

	return msgs, toolMap
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

	// Format messages with tools injected
	msgs, _ := FormatTraeMessagesWithTools(root)
	if msgs != nil {
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

	// Format messages with tools injected
	msgs, _ := FormatTraeMessagesWithTools(root)
	if msgs != nil {
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
	return FormatOpenAINonStreamResponseWithTools(id, model, fullContent, fullReasoning, nil, usage)
}

// FormatOpenAINonStreamResponseWithTools constructs a non-streaming chat completion JSON response including tool calls.
func FormatOpenAINonStreamResponseWithTools(id, model, fullContent, fullReasoning string, toolCalls []TraeToolCall, usage *TraeTokenUsage) []byte {
	msg := map[string]any{
		"role":    "assistant",
		"content": fullContent,
	}
	if fullReasoning != "" {
		msg["reasoning_content"] = fullReasoning
	}

	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
		var tcList []map[string]any
		for _, tc := range toolCalls {
			tcList = append(tcList, map[string]any{
				"index": tc.Index,
				"id":    tc.ID,
				"type":  "function",
				"function": map[string]any{
					"name":      tc.Name,
					"arguments": tc.Args,
				},
			})
		}
		msg["tool_calls"] = tcList
	}

	choice := map[string]any{
		"index":         0,
		"message":       msg,
		"finish_reason": finishReason,
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

// TraeToolCall represents a single parsed tool call from model output.
type TraeToolCall struct {
	Index int    `json:"index"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Args  string `json:"arguments"`
}

var (
	xmlAttrRegex    = regexp.MustCompile(`(\w+)\s*=\s*["']([^"']*?)["']`)
	xmlArgKeyRegex  = regexp.MustCompile(`(?:<arg_key>)?(\w+)\s*</arg_key>\s*<arg_value>([\s\S]*?)</arg_value>`)
	xmlParamRegex   = regexp.MustCompile(`<param\s+name=["']([^"']+)["'][^>]*>([\s\S]*?)</param>`)
	reToolCall      = regexp.MustCompile(`(?s)<(?:tool_call|toolcall)(?:\s+name=["']([^"']+)["'])?[^>]*>(.*?)</(?:tool_call|toolcall)>`)
	reLooseToolCall = regexp.MustCompile(`(?s)<(?:tool_call|toolcall)(?:\s+name=["']([^"']+)["'])?[^>]*>(.*?)(?:</(?:tool_call|toolcall)>|$)`)
)

func buildToolCall(rawName string, params any, toolMap map[string]string) TraeToolCall {
	rawName = strings.TrimSpace(rawName)
	mappedName := rawName
	if toolMap != nil {
		if m, ok := toolMap[strings.ToLower(rawName)]; ok && m != "" {
			mappedName = m
		} else if m, ok := toolMap[rawName]; ok && m != "" {
			mappedName = m
		}
	}

	var argsStr string
	if params == nil {
		argsStr = "{}"
	} else if str, ok := params.(string); ok {
		trimmed := strings.TrimSpace(str)
		if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
			argsStr = trimmed
		} else {
			b, _ := json.Marshal(map[string]any{"_raw": str})
			argsStr = string(b)
		}
	} else {
		b, err := json.Marshal(params)
		if err != nil {
			argsStr = "{}"
		} else {
			argsStr = string(b)
		}
	}

	u := strings.ReplaceAll(uuid.New().String(), "-", "")
	if len(u) > 24 {
		u = u[:24]
	}
	return TraeToolCall{
		ID:   "call_" + u,
		Name: mappedName,
		Args: argsStr,
	}
}

// ParseToolcallContent parses raw tool call text (JSON or XML) into a TraeToolCall.
func ParseToolcallContent(inner string, toolMap map[string]string) (TraeToolCall, bool) {
	trimmed := strings.TrimSpace(inner)
	if trimmed == "" {
		return TraeToolCall{}, false
	}

	// 1. Direct JSON parse
	var jsonMap map[string]any
	if err := json.Unmarshal([]byte(trimmed), &jsonMap); err == nil {
		name := ""
		if n, ok := jsonMap["name"].(string); ok && n != "" {
			name = n
		} else if fn, ok := jsonMap["function"].(map[string]any); ok {
			if n, ok := fn["name"].(string); ok {
				name = n
			}
		}

		var params any
		if p, ok := jsonMap["params"]; ok {
			params = p
		} else if a, ok := jsonMap["arguments"]; ok {
			params = a
		} else if in, ok := jsonMap["input"]; ok {
			params = in
		} else if fn, ok := jsonMap["function"].(map[string]any); ok {
			if a, ok := fn["arguments"]; ok {
				params = a
			}
		}

		if name != "" {
			return buildToolCall(name, params, toolMap), true
		}
	}

	// 2. Extract embedded JSON {...}
	idxStart := strings.Index(trimmed, "{")
	idxEnd := strings.LastIndex(trimmed, "}")
	if idxStart >= 0 && idxEnd > idxStart {
		jsonPart := trimmed[idxStart : idxEnd+1]
		var subMap map[string]any
		if err := json.Unmarshal([]byte(jsonPart), &subMap); err == nil {
			name := ""
			if n, ok := subMap["name"].(string); ok && n != "" {
				name = n
			} else if fn, ok := subMap["function"].(map[string]any); ok {
				if n, ok := fn["name"].(string); ok {
					name = n
				}
			}
			var params any
			if p, ok := subMap["params"]; ok {
				params = p
			} else if a, ok := subMap["arguments"]; ok {
				params = a
			} else if in, ok := subMap["input"]; ok {
				params = in
			}
			if name != "" {
				return buildToolCall(name, params, toolMap), true
			}
		}
	}

	// 3. XML with <param name="...">
	matchesParam := xmlParamRegex.FindAllStringSubmatch(trimmed, -1)
	if len(matchesParam) > 0 {
		name := ""
		params := make(map[string]any)
		lines := strings.Split(trimmed, "\n")
		firstLine := strings.TrimSpace(lines[0])
		if !strings.HasPrefix(firstLine, "<param") {
			name = strings.Fields(firstLine)[0]
		}
		for _, m := range matchesParam {
			params[m[1]] = strings.TrimSpace(m[2])
		}
		if name != "" || len(params) > 0 {
			if name == "" && toolMap != nil {
				for _, origName := range toolMap {
					name = origName
					break
				}
			}
			return buildToolCall(name, params, toolMap), true
		}
	}

	// 4. XML with <arg_key> / <arg_value>
	matchesArg := xmlArgKeyRegex.FindAllStringSubmatch(trimmed, -1)
	if len(matchesArg) > 0 {
		fields := strings.Fields(trimmed)
		name := ""
		if len(fields) > 0 && !strings.HasPrefix(fields[0], "<") {
			name = fields[0]
		}
		params := make(map[string]any)
		for _, m := range matchesArg {
			params[m[1]] = strings.TrimSpace(m[2])
		}
		if name != "" || len(params) > 0 {
			return buildToolCall(name, params, toolMap), true
		}
	}

	// 5. DSML format: <[｜|]DSML[｜|] invoke name="Name">...<[｜|]DSML[｜|] parameter name="param">value</[｜|]DSML[｜|] parameter>
	if strings.Contains(trimmed, "DSML") || strings.Contains(trimmed, "dsml") {
		name := ""
		reName := regexp.MustCompile(`(?i)<[｜|]dsml[｜|]\s+invoke\s+name=["']([^"']+)["']`)
		if m := reName.FindStringSubmatch(trimmed); len(m) > 1 {
			name = m[1]
		}
		paramMatches := regexp.MustCompile(`(?is)<[｜|]dsml[｜|]\s+parameter\s+name=["']([^"']+)["'][^>]*>(.*?)</[｜|]dsml[｜|]\s+parameter>`).FindAllStringSubmatch(trimmed, -1)
		if len(paramMatches) > 0 || name != "" {
			params := make(map[string]any)
			for _, pm := range paramMatches {
				pName := pm[1]
				pVal := strings.TrimSpace(pm[2])
				params[pName] = pVal
			}
			return buildToolCall(name, params, toolMap), true
		}
	}

	// 6. XML attribute style: ToolName key="value"
	fields := strings.Fields(trimmed)
	if len(fields) > 0 && !strings.HasPrefix(fields[0], "<") {
		name := fields[0]
		attrMatches := xmlAttrRegex.FindAllStringSubmatch(trimmed, -1)
		if len(attrMatches) > 0 {
			params := make(map[string]any)
			for _, m := range attrMatches {
				params[m[1]] = m[2]
			}
			return buildToolCall(name, params, toolMap), true
		}
	}

	return TraeToolCall{}, false
}

// ExtractToolCallsFromText extracts all <toolcall> and DSML tags from full text.
func ExtractToolCallsFromText(text string, toolMap map[string]string) []TraeToolCall {
	var calls []TraeToolCall
	matches := reToolCall.FindAllStringSubmatch(text, -1)
	idx := 0
	for _, m := range matches {
		rawInner := m[2]
		if tc, ok := ParseToolcallContent(rawInner, toolMap); ok {
			tc.Index = idx
			idx++
			calls = append(calls, tc)
		}
	}
	// Check DSML invokes
	reDsml := regexp.MustCompile(`(?is)<[｜|]dsml[｜|]\s+invoke\s+name=["']([^"']+)["'][^>]*>(.*?)(?:</[｜|]dsml[｜|]\s+invoke>|$)`)
	dsmlMatches := reDsml.FindAllStringSubmatch(text, -1)
	for _, m := range dsmlMatches {
		if tc, ok := ParseToolcallContent(m[0], toolMap); ok {
			tc.Index = idx
			idx++
			calls = append(calls, tc)
		}
	}
	if len(calls) == 0 {
		// Try loose unclosed match
		looseMatches := reLooseToolCall.FindAllStringSubmatch(text, -1)
		for _, m := range looseMatches {
			rawInner := strings.TrimSpace(m[2])
			if rawInner == "" {
				continue
			}
			if tc, ok := ParseToolcallContent(rawInner, toolMap); ok {
				tc.Index = idx
				idx++
				calls = append(calls, tc)
			}
		}
	}
	return calls
}

// StripToolCallsFromText removes <toolcall> and DSML tags from generated content.
func StripToolCallsFromText(text string) string {
	re := regexp.MustCompile(`(?s)<(?:tool_call|toolcall|function_call|functioncall)(?:\s[^>]*)?>.*?(</(?:tool_call|toolcall|function_call|functioncall)>|$)`)
	text = re.ReplaceAllString(text, "")
	reDsml := regexp.MustCompile(`(?is)<[｜|]dsml[｜|]\s+invoke(?:\s[^>]*)?>.*?(</[｜|]dsml[｜|]\s+invoke>|$)`)
	text = reDsml.ReplaceAllString(text, "")
	reDsmlOther := regexp.MustCompile(`(?is)</?[｜|]dsml[｜|][^>]*>`)
	text = reDsmlOther.ReplaceAllString(text, "")
	return strings.TrimSpace(text)
}

// FormatOpenAIStreamToolCallChunk constructs an SSE chunk with delta.tool_calls in OpenAI format.
func FormatOpenAIStreamToolCallChunk(id, model string, calls []TraeToolCall) []byte {
	if len(calls) == 0 {
		return nil
	}

	var toolCallsList []map[string]any
	for _, call := range calls {
		toolCallsList = append(toolCallsList, map[string]any{
			"index": call.Index,
			"id":    call.ID,
			"type":  "function",
			"function": map[string]any{
				"name":      call.Name,
				"arguments": call.Args,
			},
		})
	}

	choice := map[string]any{
		"index": 0,
		"delta": map[string]any{
			"tool_calls": toolCallsList,
		},
		"finish_reason": nil,
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

func isContainerTag(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "<|dsml| calls") ||
		strings.HasPrefix(lower, "<｜dsml｜ calls") ||
		strings.HasPrefix(lower, "</|dsml| calls") ||
		strings.HasPrefix(lower, "</｜dsml｜ calls") ||
		strings.HasPrefix(lower, "<|tool calls|") ||
		strings.HasPrefix(lower, "<｜tool calls｜") ||
		strings.HasPrefix(lower, "</|tool calls|") ||
		strings.HasPrefix(lower, "</｜tool calls｜")
}

func isToolCallPrefix(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix("<toolcall>", lower) ||
		strings.HasPrefix("<tool_call>", lower) ||
		strings.HasPrefix("<toolcall ", lower) ||
		strings.HasPrefix("<tool_call ", lower) ||
		strings.HasPrefix("<function_call>", lower) ||
		strings.HasPrefix("<function_call ", lower) ||
		strings.HasPrefix("<functioncall>", lower) ||
		strings.HasPrefix("<functioncall ", lower) ||
		strings.HasPrefix("<|dsml|", lower) ||
		strings.HasPrefix("<｜dsml｜", lower) ||
		strings.HasPrefix("</|dsml|", lower) ||
		strings.HasPrefix("</｜dsml｜", lower) ||
		strings.HasPrefix("<|tool", lower) ||
		strings.HasPrefix("<｜tool", lower)
}

func isToolCallTag(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "<toolcall>") ||
		strings.HasPrefix(lower, "<tool_call>") ||
		strings.HasPrefix(lower, "<toolcall ") ||
		strings.HasPrefix(lower, "<tool_call ") ||
		strings.HasPrefix(lower, "<function_call>") ||
		strings.HasPrefix(lower, "<function_call ") ||
		strings.HasPrefix(lower, "<functioncall>") ||
		strings.HasPrefix(lower, "<functioncall ") ||
		strings.HasPrefix(lower, "<|dsml| invoke") ||
		strings.HasPrefix(lower, "<｜dsml｜ invoke")
}

// ToolCallStreamFilter buffers streaming chunks, hides <toolcall> tags from text output,
// and extracts TraeToolCall events to send to clients.
type ToolCallStreamFilter struct {
	toolMap         map[string]string
	inToolCall      bool
	toolCallBuffer  strings.Builder
	accumulatedText strings.Builder
	emittedCalls    []TraeToolCall
	callCount       int
}

// NewToolCallStreamFilter creates a filter for stripping and parsing tool calls in stream.
func NewToolCallStreamFilter(toolMap map[string]string) *ToolCallStreamFilter {
	return &ToolCallStreamFilter{
		toolMap: toolMap,
	}
}

// Feed receives a text chunk from upstream and returns filtered text and any detected tool calls.
func (f *ToolCallStreamFilter) Feed(chunk string) (string, []TraeToolCall) {
	if chunk == "" {
		return "", nil
	}
	f.accumulatedText.WriteString(chunk)

	var textOut strings.Builder
	var newCalls []TraeToolCall

	for i := 0; i < len(chunk); i++ {
		ch := chunk[i]

		if f.inToolCall {
			f.toolCallBuffer.WriteByte(ch)
			bufStr := f.toolCallBuffer.String()

			closingTag := ""
			lowerBuf := strings.ToLower(bufStr)
			if strings.HasSuffix(lowerBuf, "</toolcall>") {
				closingTag = "</toolcall>"
			} else if strings.HasSuffix(lowerBuf, "</tool_call>") {
				closingTag = "</tool_call>"
			} else if strings.HasSuffix(lowerBuf, "</function_call>") {
				closingTag = "</function_call>"
			} else if strings.HasSuffix(lowerBuf, "</functioncall>") {
				closingTag = "</functioncall>"
			} else if strings.HasSuffix(lowerBuf, "</|dsml| invoke>") {
				closingTag = "</|dsml| invoke>"
			} else if strings.HasSuffix(lowerBuf, "</｜dsml｜ invoke>") {
				closingTag = "</｜dsml｜ invoke>"
			}

			if closingTag != "" {
				inner := bufStr[:len(bufStr)-len(closingTag)]
				tc, ok := ParseToolcallContent(inner, f.toolMap)
				if ok {
					tc.Index = f.callCount
					f.callCount++
					f.emittedCalls = append(f.emittedCalls, tc)
					newCalls = append(newCalls, tc)
				}
				f.inToolCall = false
				f.toolCallBuffer.Reset()
			}
		} else {
			f.toolCallBuffer.WriteByte(ch)
			bufStr := f.toolCallBuffer.String()

			if ch == '>' {
				// Check if this formed a container tag or a tool call start
				ltIdx := strings.LastIndex(bufStr, "<")
				if ltIdx >= 0 {
					tagCandidate := bufStr[ltIdx:]
					if isContainerTag(tagCandidate) {
						if ltIdx > 0 {
							textOut.WriteString(bufStr[:ltIdx])
						}
						f.toolCallBuffer.Reset()
						continue
					}
					if isToolCallTag(tagCandidate) {
						f.inToolCall = true
						if ltIdx > 0 {
							textOut.WriteString(bufStr[:ltIdx])
						}
						f.toolCallBuffer.Reset()
						f.toolCallBuffer.WriteString(tagCandidate)
						continue
					}
				}
			}

			// If buffer doesn't look like an in-progress tag, flush text
			ltIdx := strings.LastIndex(bufStr, "<")
			if ltIdx == -1 {
				textOut.WriteString(bufStr)
				f.toolCallBuffer.Reset()
			} else if ltIdx > 0 {
				candidate := bufStr[ltIdx:]
				if !isToolCallPrefix(candidate) {
					textOut.WriteString(bufStr)
					f.toolCallBuffer.Reset()
				} else {
					textOut.WriteString(bufStr[:ltIdx])
					f.toolCallBuffer.Reset()
					f.toolCallBuffer.WriteString(candidate)
				}
			} else if !isToolCallPrefix(bufStr) && f.toolCallBuffer.Len() > 30 {
				textOut.WriteString(bufStr)
				f.toolCallBuffer.Reset()
			}
		}
	}

	return textOut.String(), newCalls
}

// Flush flushes remaining buffer content and recovers any incomplete tool calls.
func (f *ToolCallStreamFilter) Flush() (string, []TraeToolCall) {
	var textOut strings.Builder
	var finalCalls []TraeToolCall

	bufStr := f.toolCallBuffer.String()
	if bufStr != "" {
		if f.inToolCall {
			tc, ok := ParseToolcallContent(bufStr, f.toolMap)
			if ok {
				tc.Index = f.callCount
				f.callCount++
				f.emittedCalls = append(f.emittedCalls, tc)
				finalCalls = append(finalCalls, tc)
			}
		} else {
			textOut.WriteString(bufStr)
		}
		f.toolCallBuffer.Reset()
		f.inToolCall = false
	}

	// Secondary check: ensure no toolcall was missed in accumulated text
	extracted := ExtractToolCallsFromText(f.accumulatedText.String(), f.toolMap)
	for _, tc := range extracted {
		alreadyEmitted := false
		for _, em := range f.emittedCalls {
			if em.Name == tc.Name && em.Args == tc.Args {
				alreadyEmitted = true
				break
			}
		}
		if !alreadyEmitted {
			tc.Index = f.callCount
			f.callCount++
			f.emittedCalls = append(f.emittedCalls, tc)
			finalCalls = append(finalCalls, tc)
		}
	}

	return textOut.String(), finalCalls
}

// HasEmittedCalls returns whether any tool calls were emitted by this filter.
func (f *ToolCallStreamFilter) HasEmittedCalls() bool {
	return len(f.emittedCalls) > 0
}
