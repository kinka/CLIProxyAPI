package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	traeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/trae"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
)

const (
	TraeChatPath = "/api/agent/v3/llm_utils_chat"
)

func mapTraeErrorCode(code int) int {
	switch code {
	case 4001, 4000:
		return http.StatusBadRequest
	case 4010, 4003:
		return http.StatusUnauthorized
	case 4011, 429:
		return http.StatusTooManyRequests
	case 4023:
		return http.StatusBadGateway
	default:
		if code >= 100 && code <= 599 {
			return code
		}
		return http.StatusBadGateway
	}
}

// TraeExecutor is a native executor for Trae API using OpenAI-compatible or direct Trae protocol.
type TraeExecutor struct {
	cfg *config.Config
}

// NewTraeExecutor creates a new Trae executor instance.
func NewTraeExecutor(cfg *config.Config) *TraeExecutor {
	return &TraeExecutor{
		cfg: cfg,
	}
}

// Identifier returns the executor identifier.
func (e *TraeExecutor) Identifier() string {
	return "trae"
}

// RequestToFormat reports the upstream request format used for Trae.
func (e *TraeExecutor) RequestToFormat(_ cliproxyexecutor.Request, opts cliproxyexecutor.Options) sdktranslator.Format {
	if opts.SourceFormat == sdktranslator.FormatClaude {
		return sdktranslator.FormatClaude
	}
	if opts.SourceFormat == sdktranslator.FormatOpenAIResponse {
		return sdktranslator.FormatOpenAIResponse
	}
	return sdktranslator.FormatOpenAI
}

func traeStorageFromAuth(auth *cliproxyauth.Auth) *traeauth.TraeTokenStorage {
	if auth == nil {
		return &traeauth.TraeTokenStorage{Host: traeauth.DefaultHostCN}
	}
	if ts, ok := auth.Storage.(*traeauth.TraeTokenStorage); ok && ts != nil {
		return ts
	}
	token := ""
	if auth.Metadata != nil {
		if t, ok := auth.Metadata["access_token"].(string); ok && t != "" {
			token = t
		} else if t, ok := auth.Metadata["token"].(string); ok && t != "" {
			token = t
		}
	}
	if token == "" && auth.Attributes != nil {
		if t, ok := auth.Attributes["api_key"]; ok && t != "" {
			token = t
		} else if t, ok := auth.Attributes["token"]; ok && t != "" {
			token = t
		}
	}
	host := traeauth.DefaultHostCN
	if auth.Attributes != nil {
		if h, ok := auth.Attributes["base_url"]; ok && h != "" {
			host = h
		}
	}
	edition := "cn"
	if auth.Attributes != nil {
		if ed, ok := auth.Attributes["edition"]; ok && ed != "" {
			edition = ed
		}
	}
	var machineID, deviceID, userID string
	if auth.Metadata != nil {
		if m, ok := auth.Metadata["machine_id"].(string); ok {
			machineID = m
		}
		if d, ok := auth.Metadata["device_id"].(string); ok {
			deviceID = d
		}
		if u, ok := auth.Metadata["user_id"].(string); ok {
			userID = u
		}
	}
	return &traeauth.TraeTokenStorage{
		AccessToken: token,
		Host:        host,
		Edition:     edition,
		MachineID:   machineID,
		DeviceID:    deviceID,
		UserID:      userID,
		Type:        "trae",
	}
}

// PrepareRequest injects Trae credentials and headers into the outgoing HTTP request.
func (e *TraeExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	storage := traeStorageFromAuth(auth)
	helps.ApplyTraeHeaders(req, storage, false)
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects Trae credentials into the request and executes it.
func (e *TraeExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("trae executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

// Refresh checks and refreshes Trae OAuth tokens if expiring.
func (e *TraeExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, fmt.Errorf("trae executor: auth is nil")
	}
	storage := traeStorageFromAuth(auth)
	if storage.RefreshToken == "" {
		return auth, nil
	}

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	resp, err := traeauth.ExchangeToken(ctx, httpClient, storage.AuthHost, storage.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("trae refresh failed: %w", err)
	}

	cloned := auth.Clone()
	if cloned.Metadata == nil {
		cloned.Metadata = make(map[string]any)
	}
	cloned.Metadata["access_token"] = resp.Token
	cloned.Metadata["refresh_token"] = resp.RefreshToken
	cloned.Metadata["expired"] = resp.ExpiredAt
	cloned.Metadata["refresh_expired"] = resp.RefreshExpiredAt
	cloned.LastRefreshedAt = time.Now()

	newStorage := *storage
	newStorage.AccessToken = resp.Token
	newStorage.RefreshToken = resp.RefreshToken
	newStorage.Expired = resp.ExpiredAt
	newStorage.RefreshExpired = resp.RefreshExpiredAt
	cloned.Storage = &newStorage

	return cloned, nil
}

// Execute performs a non-streaming chat completion request to Trae.
func (e *TraeExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	from := opts.SourceFormat
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	to := sdktranslator.FromString("openai")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := bytes.Clone(originalPayloadSource)
	openAIPayload := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, bytes.Clone(req.Payload), false)

	storage := traeStorageFromAuth(auth)
	traeBody, _, err := helps.BuildTraeRequestBody(openAIPayload, baseModel, storage, true)
	if err != nil {
		return resp, fmt.Errorf("trae executor: failed to build request payload: %w", err)
	}

	apiHost := storage.Host
	if apiHost == "" {
		apiHost = traeauth.DefaultHostCN
	}
	apiHost = strings.TrimRight(apiHost, "/")
	url := apiHost + TraeChatPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(traeBody))
	if err != nil {
		return resp, err
	}
	helps.ApplyTraeHeaders(httpReq, storage, true)
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(httpReq, auth.Attributes)
	}

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      traeBody,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("trae executor: close response body error: %v", errClose)
		}
	}()

	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return resp, err
	}

	// Parse SSE stream to accumulate full content and usage
	scanner := bufio.NewScanner(httpResp.Body)
	scanner.Buffer(nil, 1048576)
	var currentEvent string
	var fullContent strings.Builder
	var fullReasoning strings.Builder
	var lastUsage *helps.TraeTokenUsage

	for scanner.Scan() {
		line := scanner.Text()
		helps.AppendAPIResponseChunk(ctx, e.cfg, []byte(line+"\n"))
		parsed := helps.ParseTraeSSELine(line, &currentEvent)
		if parsed == nil {
			continue
		}
		if parsed.Type == "text" {
			if parsed.Content != "" {
				fullContent.WriteString(parsed.Content)
			}
			if parsed.Reasoning != "" {
				fullReasoning.WriteString(parsed.Reasoning)
			}
		} else if parsed.Type == "token_usage" && parsed.TokenUsage != nil {
			lastUsage = parsed.TokenUsage
		} else if parsed.Type == "error" {
			err = statusErr{code: mapTraeErrorCode(parsed.ErrorCode), msg: parsed.ErrorMessage}
			return resp, err
		}
	}

	if errScan := scanner.Err(); errScan != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, errScan)
		return resp, errScan
	}

	compID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	openAIRespJSON := helps.FormatOpenAINonStreamResponse(compID, req.Model, fullContent.String(), fullReasoning.String(), lastUsage)

	if lastUsage != nil {
		reporter.Publish(ctx, helps.ParseOpenAIUsage(openAIRespJSON))
	}

	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, responseFormat, req.Model, originalPayload, openAIPayload, openAIRespJSON, &param)
	resp = cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}
	return resp, nil
}

// ExecuteStream performs a streaming chat completion request to Trae.
func (e *TraeExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	from := opts.SourceFormat
	responseFormat := cliproxyexecutor.ResponseFormatOrSource(opts)
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	to := sdktranslator.FromString("openai")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := bytes.Clone(originalPayloadSource)
	openAIPayload := helps.TranslateRequestWithCodexMultiAgentV2(ctx, opts.Headers, e.cfg, from, to, baseModel, bytes.Clone(req.Payload), true)

	storage := traeStorageFromAuth(auth)
	traeBody, _, err := helps.BuildTraeRequestBody(openAIPayload, baseModel, storage, true)
	if err != nil {
		return nil, fmt.Errorf("trae executor: failed to build request payload: %w", err)
	}

	apiHost := storage.Host
	if apiHost == "" {
		apiHost = traeauth.DefaultHostCN
	}
	apiHost = strings.TrimRight(apiHost, "/")
	url := apiHost + TraeChatPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(traeBody))
	if err != nil {
		return nil, err
	}
	helps.ApplyTraeHeaders(httpReq, storage, true)
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(httpReq, auth.Attributes)
	}

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      traeBody,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}

	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("trae executor: close response body error: %v", errClose)
		}
		return nil, statusErr{code: httpResp.StatusCode, msg: string(b)}
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	compID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())

	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("trae executor: close stream body error: %v", errClose)
			}
		}()

		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 1048576)
		claudeInputTokens := helps.NewClaudeInputTokenState(from, to, responseFormat, originalPayload)
		var currentEvent string
		var param any
		var streamUsage helps.StreamUsageBuffer
		defer streamUsage.Publish(ctx, reporter)

		for scanner.Scan() {
			line := scanner.Text()
			helps.AppendAPIResponseChunk(ctx, e.cfg, []byte(line+"\n"))

			parsed := helps.ParseTraeSSELine(line, &currentEvent)
			if parsed == nil {
				continue
			}

			if parsed.Type == "text" {
				chunkJSON := helps.FormatOpenAIStreamChunk(compID, req.Model, parsed.Content, parsed.Reasoning, "")
				lineChunk := append([]byte("data: "), chunkJSON...)
				lineChunk = append(lineChunk, []byte("\n\n")...)

				chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, openAIPayload, bytes.Clone(lineChunk), &param, claudeInputTokens)
				for i := range chunks {
					select {
					case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
					case <-ctx.Done():
						return
					}
				}
			} else if parsed.Type == "token_usage" && parsed.TokenUsage != nil {
				usageChunk := map[string]any{
					"id":      compID,
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   req.Model,
					"choices": []any{},
					"usage": map[string]any{
						"prompt_tokens":     parsed.TokenUsage.PromptTokens,
						"completion_tokens": parsed.TokenUsage.CompletionTokens,
						"total_tokens":      parsed.TokenUsage.TotalTokens,
					},
				}
				b, _ := json.Marshal(usageChunk)
				streamUsage.ObserveOpenAIStream(b)
			} else if parsed.Type == "error" {
				streamErr := statusErr{code: mapTraeErrorCode(parsed.ErrorCode), msg: parsed.ErrorMessage}
				helps.RecordAPIResponseError(ctx, e.cfg, streamErr)
				reporter.PublishFailure(ctx, streamErr)
				select {
				case out <- cliproxyexecutor.StreamChunk{Err: streamErr}:
				case <-ctx.Done():
				}
				return
			} else if parsed.Type == "done" {
				doneChunkJSON := helps.FormatOpenAIStreamChunk(compID, req.Model, "", "", parsed.FinishReason)
				lineChunk := append([]byte("data: "), doneChunkJSON...)
				lineChunk = append(lineChunk, []byte("\n\n")...)

				chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, openAIPayload, bytes.Clone(lineChunk), &param, claudeInputTokens)
				for i := range chunks {
					select {
					case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
					case <-ctx.Done():
						return
					}
				}

				// Terminal [DONE]
				doneChunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, openAIPayload, []byte("data: [DONE]\n\n"), &param, claudeInputTokens)
				for i := range doneChunks {
					select {
					case out <- cliproxyexecutor.StreamChunk{Payload: doneChunks[i]}:
					case <-ctx.Done():
						return
					}
				}
				return
			}
		}

		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: errScan}:
			case <-ctx.Done():
			}
		}
	}()

	return &cliproxyexecutor.StreamResult{
		Headers: httpResp.Header.Clone(),
		Chunks:  out,
	}, nil
}

// CountTokens provides token counting for Trae.
func (e *TraeExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	// Trae counts can be wrapped via standard translator
	return cliproxyexecutor.Response{}, nil
}
