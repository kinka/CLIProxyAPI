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
	TraeChatPath    = "/api/agent/v3/llm_utils_chat"
	TraeRawChatPath = "/api/ide/v2/llm_raw_chat"
)

type traeEndpointPlan struct {
	name      string
	path      string
	isRaw     bool
	buildBody func(rawPayload []byte, requestedModel string, storage *traeauth.TraeTokenStorage, stream bool) ([]byte, string, error)
}

func getTraeEndpointPlans(baseModel string) []traeEndpointPlan {
	rawPlan := traeEndpointPlan{
		name:      "llm_raw_chat",
		path:      TraeRawChatPath,
		isRaw:     true,
		buildBody: helps.BuildTraeRawChatRequestBody,
	}
	utilsPlan := traeEndpointPlan{
		name:      "llm_utils_chat",
		path:      TraeChatPath,
		isRaw:     false,
		buildBody: helps.BuildTraeRequestBody,
	}

	if helps.ModelPrefersRawChat(baseModel) {
		return []traeEndpointPlan{rawPlan, utilsPlan}
	}
	return []traeEndpointPlan{utilsPlan, rawPlan}
}

type streamPeekReader struct {
	io.Reader
	closer io.Closer
}

func (s *streamPeekReader) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

func peekFirstTraeEvent(resp *http.Response) (io.ReadCloser, *statusErr, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil, fmt.Errorf("response body is nil")
	}

	reader := bufio.NewReader(resp.Body)
	var peekedBytes bytes.Buffer
	var currentEvent string
	var hasContent bool
	var streamErr *statusErr

	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			peekedBytes.WriteString(line)
			parsed := helps.ParseTraeSSELine(line, &currentEvent)
			if parsed != nil {
				if parsed.Type == "text" && (parsed.Content != "" || parsed.Reasoning != "") {
					hasContent = true
					break
				}
				if parsed.Type == "error" {
					streamErr = &statusErr{code: mapTraeErrorCode(parsed.ErrorCode), msg: parsed.ErrorMessage}
					break
				}
				if parsed.Type == "token_usage" || parsed.Type == "done" {
					break
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, err
		}
	}

	if streamErr != nil && !hasContent {
		_ = resp.Body.Close()
		return nil, streamErr, nil
	}

	combined := &streamPeekReader{
		Reader: io.MultiReader(bytes.NewReader(peekedBytes.Bytes()), reader),
		closer: resp.Body,
	}
	return combined, nil, nil
}

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
	var refreshToken, host, authHost, edition, machineID, deviceID, userID, userRegion string
	var expired, refreshExpired string

	if auth.Metadata != nil {
		if t, ok := auth.Metadata["access_token"].(string); ok && t != "" {
			token = t
		} else if t, ok := auth.Metadata["token"].(string); ok && t != "" {
			token = t
		}
		if rt, ok := auth.Metadata["refresh_token"].(string); ok {
			refreshToken = rt
		}
		if h, ok := auth.Metadata["host"].(string); ok && h != "" {
			host = h
		}
		if ah, ok := auth.Metadata["auth_host"].(string); ok && ah != "" {
			authHost = ah
		}
		if ed, ok := auth.Metadata["edition"].(string); ok && ed != "" {
			edition = ed
		}
		if m, ok := auth.Metadata["machine_id"].(string); ok {
			machineID = m
		}
		if d, ok := auth.Metadata["device_id"].(string); ok {
			deviceID = d
		}
		if u, ok := auth.Metadata["user_id"].(string); ok {
			userID = u
		}
		if ur, ok := auth.Metadata["user_region"].(string); ok {
			userRegion = ur
		}
		if exp, ok := auth.Metadata["expired"].(string); ok {
			expired = exp
		} else if exp, ok := auth.Metadata["expired"].(float64); ok {
			expired = fmt.Sprintf("%.0f", exp)
		}
		if rexp, ok := auth.Metadata["refresh_expired"].(string); ok {
			refreshExpired = rexp
		} else if rexp, ok := auth.Metadata["refresh_expired"].(float64); ok {
			refreshExpired = fmt.Sprintf("%.0f", rexp)
		}
	}
	if token == "" && auth.Attributes != nil {
		if t, ok := auth.Attributes["api_key"]; ok && t != "" {
			token = t
		} else if t, ok := auth.Attributes["token"]; ok && t != "" {
			token = t
		}
	}
	if auth.Attributes != nil {
		if h, ok := auth.Attributes["base_url"]; ok && h != "" {
			host = h
		}
		if ed, ok := auth.Attributes["edition"]; ok && ed != "" {
			edition = ed
		}
	}
	if host == "" {
		if strings.EqualFold(edition, "sg") {
			host = traeauth.DefaultHostSG
		} else {
			host = traeauth.DefaultHostCN
		}
	}
	if edition == "" {
		edition = "cn"
	}
	return &traeauth.TraeTokenStorage{
		AccessToken:    token,
		RefreshToken:   refreshToken,
		Expired:        expired,
		RefreshExpired: refreshExpired,
		Host:           host,
		AuthHost:       authHost,
		Edition:        edition,
		MachineID:      machineID,
		DeviceID:       deviceID,
		UserID:         userID,
		UserRegion:     userRegion,
		Type:           "trae",
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
	apiHost := storage.Host
	if apiHost == "" {
		apiHost = traeauth.DefaultHostCN
	}
	apiHost = strings.TrimRight(apiHost, "/")

	plans := getTraeEndpointPlans(baseModel)
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)

	var lastErr error
	var httpResp *http.Response
	var chosenPlan traeEndpointPlan
	var chosenURL string
	var fullContent strings.Builder
	var fullReasoning strings.Builder
	var lastUsage *helps.TraeTokenUsage

	for i, plan := range plans {
		traeBody, _, errBuild := plan.buildBody(openAIPayload, baseModel, storage, true)
		if errBuild != nil {
			lastErr = fmt.Errorf("trae executor: failed to build %s payload: %w", plan.name, errBuild)
			continue
		}

		url := apiHost + plan.path
		httpReq, errReq := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(traeBody))
		if errReq != nil {
			lastErr = errReq
			continue
		}
		helps.ApplyTraeHeaders(httpReq, storage, true)
		if plan.isRaw {
			httpReq.Header.Set("X-App-Function", "solo_agent")
			httpReq.Header.Set("X-Ide-Function", "solo_agent")
		}
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

		respDo, errDo := httpClient.Do(httpReq)
		if errDo != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errDo)
			lastErr = errDo
			continue
		}

		helps.RecordAPIResponseMetadata(ctx, e.cfg, respDo.StatusCode, respDo.Header.Clone())
		if respDo.StatusCode < 200 || respDo.StatusCode >= 300 {
			b, _ := io.ReadAll(respDo.Body)
			_ = respDo.Body.Close()
			helps.AppendAPIResponseChunk(ctx, e.cfg, b)
			lastErr = statusErr{code: respDo.StatusCode, msg: string(b)}
			if i < len(plans)-1 {
				log.Warnf("trae executor: %s returned HTTP %d, falling back to next endpoint", plan.name, respDo.StatusCode)
				continue
			}
			err = lastErr
			return resp, err
		}

		// Parse SSE stream
		scanner := bufio.NewScanner(respDo.Body)
		scanner.Buffer(nil, 1048576)
		var currentEvent string
		var streamErr *statusErr
		fullContent.Reset()
		fullReasoning.Reset()
		lastUsage = nil

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
				streamErr = &statusErr{code: mapTraeErrorCode(parsed.ErrorCode), msg: parsed.ErrorMessage}
			}
		}
		_ = respDo.Body.Close()

		if streamErr != nil && fullContent.Len() == 0 && fullReasoning.Len() == 0 {
			lastErr = streamErr
			if i < len(plans)-1 {
				log.Warnf("trae executor: %s returned stream error: %v, falling back", plan.name, streamErr)
				continue
			}
			err = lastErr
			return resp, err
		}

		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			lastErr = errScan
			if i < len(plans)-1 {
				continue
			}
			return resp, errScan
		}

		httpResp = respDo
		chosenPlan = plan
		chosenURL = url
		break
	}

	if httpResp == nil {
		if lastErr != nil {
			err = lastErr
			return resp, err
		}
		err = fmt.Errorf("trae executor: all chat endpoints failed")
		return resp, err
	}

	compID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	toolMap := helps.ExtractToolMapFromPayload(openAIPayload, originalPayload)
	toolCalls := helps.ExtractToolCallsFromText(fullContent.String(), toolMap)
	cleanContent := fullContent.String()
	if len(toolCalls) > 0 {
		cleanContent = helps.StripToolCallsFromText(cleanContent)
	} else if helps.IsTransitionalDeferralText(strings.TrimSpace(cleanContent)) {
		// Auto-drive turn for conversational deferral in non-streaming mode
		accumulatedText := strings.TrimSpace(cleanContent)
		prompt := fmt.Sprintf("【Agent Action Rule: You stated: %q. DO NOT merely explain or pause. Call the next tool immediately using <toolcall> to execute your action now.】", accumulatedText)
		if newPayload, errAppend := helps.AppendMessagesToPayload(openAIPayload,
			map[string]any{"role": "assistant", "content": accumulatedText},
			map[string]any{"role": "user", "content": prompt},
		); errAppend == nil {
			if newTraeBody, _, errNewBuild := chosenPlan.buildBody(newPayload, baseModel, storage, false); errNewBuild == nil {
				if newReq, errNewReq := http.NewRequestWithContext(ctx, http.MethodPost, chosenURL, bytes.NewReader(newTraeBody)); errNewReq == nil {
					helps.ApplyTraeHeaders(newReq, storage, false)
					if chosenPlan.isRaw {
						newReq.Header.Set("X-App-Function", "solo_agent")
						newReq.Header.Set("X-Ide-Function", "solo_agent")
					}
					if auth != nil {
						util.ApplyCustomHeadersFromAttrs(newReq, auth.Attributes)
					}
					if newResp, errNewDo := httpClient.Do(newReq); errNewDo == nil && newResp.StatusCode >= 200 && newResp.StatusCode < 300 {
						defer newResp.Body.Close()
						var secondContent strings.Builder
						scanner2 := bufio.NewScanner(newResp.Body)
						scanner2.Buffer(nil, 1048576)
						var ev2 string
						for scanner2.Scan() {
							line := scanner2.Text()
							p := helps.ParseTraeSSELine(line, &ev2)
							if p != nil && p.Type == "text" && p.Content != "" {
								secondContent.WriteString(p.Content)
							}
						}
						if moreCalls := helps.ExtractToolCallsFromText(secondContent.String(), toolMap); len(moreCalls) > 0 {
							toolCalls = append(toolCalls, moreCalls...)
							cleanContent = cleanContent + "\n" + helps.StripToolCallsFromText(secondContent.String())
						}
					}
				}
			}
		}
	}
	openAIRespJSON := helps.FormatOpenAINonStreamResponseWithTools(compID, req.Model, cleanContent, fullReasoning.String(), toolCalls, lastUsage)

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
	apiHost := storage.Host
	if apiHost == "" {
		apiHost = traeauth.DefaultHostCN
	}
	apiHost = strings.TrimRight(apiHost, "/")

	plans := getTraeEndpointPlans(baseModel)
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)

	var streamBody io.ReadCloser
	var lastErr error
	var activeResp *http.Response
	var chosenPlan traeEndpointPlan
	var chosenURL string

	for i, plan := range plans {
		traeBody, _, errBuild := plan.buildBody(openAIPayload, baseModel, storage, true)
		if errBuild != nil {
			lastErr = fmt.Errorf("trae executor: failed to build %s payload: %w", plan.name, errBuild)
			continue
		}

		url := apiHost + plan.path
		httpReq, errReq := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(traeBody))
		if errReq != nil {
			lastErr = errReq
			continue
		}
		helps.ApplyTraeHeaders(httpReq, storage, true)
		if plan.isRaw {
			httpReq.Header.Set("X-App-Function", "solo_agent")
			httpReq.Header.Set("X-Ide-Function", "solo_agent")
		}
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

		httpResp, errDo := httpClient.Do(httpReq)
		if errDo != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errDo)
			lastErr = errDo
			continue
		}

		helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
		if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
			b, _ := io.ReadAll(httpResp.Body)
			helps.AppendAPIResponseChunk(ctx, e.cfg, b)
			_ = httpResp.Body.Close()
			lastErr = statusErr{code: httpResp.StatusCode, msg: string(b)}
			if i < len(plans)-1 {
				log.Warnf("trae executor stream: %s HTTP %d, falling back", plan.name, httpResp.StatusCode)
				continue
			}
			return nil, lastErr
		}

		peekedBody, peekErr, errPeek := peekFirstTraeEvent(httpResp)
		if errPeek != nil {
			_ = httpResp.Body.Close()
			lastErr = errPeek
			continue
		}
		if peekErr != nil {
			lastErr = *peekErr
			if i < len(plans)-1 {
				log.Warnf("trae executor stream: %s returned early stream error: %v, falling back", plan.name, peekErr)
				continue
			}
			return nil, lastErr
		}

		streamBody = peekedBody
		chosenPlan = plan
		chosenURL = url
		activeResp = httpResp
		break
	}

	if streamBody == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("trae executor: all chat stream endpoints failed")
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	compID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())

	go func() {
		defer close(out)
		currentStreamBody := streamBody
		defer func() {
			if currentStreamBody != nil {
				if errClose := currentStreamBody.Close(); errClose != nil {
					log.Errorf("trae executor: close stream body error: %v", errClose)
				}
			}
		}()

		currentPayload := openAIPayload
		scanner := bufio.NewScanner(currentStreamBody)
		scanner.Buffer(nil, 1048576)
		claudeInputTokens := helps.NewClaudeInputTokenState(from, to, responseFormat, originalPayload)
		var currentEvent string
		var param any
		var streamUsage helps.StreamUsageBuffer
		defer streamUsage.Publish(ctx, reporter)

		toolMap := helps.ExtractToolMapFromPayload(currentPayload, originalPayload)
		toolFilter := helps.NewToolCallStreamFilter(toolMap)
		var fullAssistantContent strings.Builder
		autoDriveCount := 0
		const maxAutoDrive = 3

		for scanner.Scan() {
			line := scanner.Text()
			helps.AppendAPIResponseChunk(ctx, e.cfg, []byte(line+"\n"))

			parsed := helps.ParseTraeSSELine(line, &currentEvent)
			if parsed == nil {
				continue
			}

			if parsed.Type == "text" {
				if parsed.Reasoning != "" {
					chunkJSON := helps.FormatOpenAIStreamChunk(compID, req.Model, "", parsed.Reasoning, "")
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
				}

				if parsed.Content != "" {
					cleanText, newCalls := toolFilter.Feed(parsed.Content)
					if cleanText != "" {
						fullAssistantContent.WriteString(cleanText)
						chunkJSON := helps.FormatOpenAIStreamChunk(compID, req.Model, cleanText, "", "")
						lineChunk := append([]byte("data: "), chunkJSON...)
						lineChunk = append(lineChunk, []byte("\n\n")...)

						chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, currentPayload, bytes.Clone(lineChunk), &param, claudeInputTokens)
						for i := range chunks {
							select {
							case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
							case <-ctx.Done():
								return
							}
						}
					}

					if len(newCalls) > 0 {
						tcChunkJSON := helps.FormatOpenAIStreamToolCallChunk(compID, req.Model, newCalls)
						if len(tcChunkJSON) > 0 {
							lineChunk := append([]byte("data: "), tcChunkJSON...)
							lineChunk = append(lineChunk, []byte("\n\n")...)

							chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, currentPayload, bytes.Clone(lineChunk), &param, claudeInputTokens)
							for i := range chunks {
								select {
								case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
								case <-ctx.Done():
									return
								}
							}
						}
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
				flushText, finalCalls := toolFilter.Flush()
				if flushText != "" {
					fullAssistantContent.WriteString(flushText)
					chunkJSON := helps.FormatOpenAIStreamChunk(compID, req.Model, flushText, "", "")
					lineChunk := append([]byte("data: "), chunkJSON...)
					lineChunk = append(lineChunk, []byte("\n\n")...)

					chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, currentPayload, bytes.Clone(lineChunk), &param, claudeInputTokens)
					for i := range chunks {
						select {
						case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
						case <-ctx.Done():
							return
						}
					}
				}

				if len(finalCalls) > 0 {
					tcChunkJSON := helps.FormatOpenAIStreamToolCallChunk(compID, req.Model, finalCalls)
					if len(tcChunkJSON) > 0 {
						lineChunk := append([]byte("data: "), tcChunkJSON...)
						lineChunk = append(lineChunk, []byte("\n\n")...)

						chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, currentPayload, bytes.Clone(lineChunk), &param, claudeInputTokens)
						for i := range chunks {
							select {
							case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
							case <-ctx.Done():
								return
							}
						}
					}
				}

				// Auto-drive check: if turn ended with an introductory deferral phrase and zero tool calls,
				// prompt the model to call the tool immediately within the same turn.
				hasEmittedCalls := toolFilter.HasEmittedCalls() || len(finalCalls) > 0
				accumulatedText := strings.TrimSpace(fullAssistantContent.String())
				// An earlier drive that came back with no content at all would otherwise fall
				// through to end_turn and stall the agent loop, so keep driving in that case too.
				emptyContinuation := accumulatedText == "" && autoDriveCount > 0
				needsAutoDrive := !hasEmittedCalls && autoDriveCount < maxAutoDrive &&
					(emptyContinuation || helps.IsTransitionalDeferralText(accumulatedText))
				if needsAutoDrive {
					autoDriveCount++
					var prompt string
					if emptyContinuation {
						log.Infof("trae executor stream: continuation returned no content and no tool call, auto-driving (attempt %d/%d)", autoDriveCount, maxAutoDrive)
						prompt = "【Agent Action Rule: Your previous reply was empty. DO NOT pause or explain. Call the next tool immediately using <toolcall> to execute your action now.】"
					} else {
						log.Infof("trae executor stream: detected transitional deferral %q with no tool call, auto-driving (attempt %d/%d)", accumulatedText, autoDriveCount, maxAutoDrive)
						prompt = fmt.Sprintf("【Agent Action Rule: You stated: %q. DO NOT pause or explain. Call the next tool immediately using <toolcall> to execute your action now.】", accumulatedText)
					}

					extraMsgs := make([]map[string]any, 0, 2)
					if accumulatedText != "" {
						extraMsgs = append(extraMsgs, map[string]any{"role": "assistant", "content": accumulatedText})
					}
					extraMsgs = append(extraMsgs, map[string]any{"role": "user", "content": prompt})
					newPayload, errAppend := helps.AppendMessagesToPayload(currentPayload, extraMsgs...)
					if errAppend == nil {
						// Back-to-back requests on the same conversation can come back empty,
						// so space the continuation out slightly before retrying.
						select {
						case <-time.After(time.Duration(autoDriveCount) * 400 * time.Millisecond):
						case <-ctx.Done():
							return
						}
						newTraeBody, _, errNewBuild := chosenPlan.buildBody(newPayload, baseModel, storage, true)
						if errNewBuild == nil {
							newReq, errNewReq := http.NewRequestWithContext(ctx, http.MethodPost, chosenURL, bytes.NewReader(newTraeBody))
							if errNewReq == nil {
								helps.ApplyTraeHeaders(newReq, storage, true)
								if chosenPlan.isRaw {
									newReq.Header.Set("X-App-Function", "solo_agent")
									newReq.Header.Set("X-Ide-Function", "solo_agent")
								}
								if auth != nil {
									util.ApplyCustomHeadersFromAttrs(newReq, auth.Attributes)
								}
								newResp, errNewDo := httpClient.Do(newReq)
								if errNewDo == nil && newResp.StatusCode >= 200 && newResp.StatusCode < 300 {
									newPeeked, peekErr, errPeek := peekFirstTraeEvent(newResp)
									if errPeek == nil && peekErr == nil {
										_ = currentStreamBody.Close()
										currentStreamBody = newPeeked
										scanner = bufio.NewScanner(currentStreamBody)
										scanner.Buffer(nil, 1048576)
										currentPayload = newPayload
										currentEvent = ""
										fullAssistantContent.Reset()
										toolFilter = helps.NewToolCallStreamFilter(toolMap)
										continue
									} else {
										log.Warnf("trae executor stream: auto-drive peek error: peekErr=%v, errPeek=%v", peekErr, errPeek)
									}
								} else {
									if errNewDo != nil {
										log.Warnf("trae executor stream: auto-drive request failed: %v", errNewDo)
									} else {
										log.Warnf("trae executor stream: auto-drive HTTP status: %d", newResp.StatusCode)
									}
								}
							} else {
								log.Warnf("trae executor stream: auto-drive create request error: %v", errNewReq)
							}
						} else {
							log.Warnf("trae executor stream: auto-drive buildBody error: %v", errNewBuild)
						}
					} else {
						log.Warnf("trae executor stream: auto-drive appendMessages error: %v", errAppend)
					}
				}

				finishReason := parsed.FinishReason
				if toolFilter.HasEmittedCalls() {
					finishReason = "tool_calls"
				} else if finishReason == "" {
					finishReason = "stop"
				}
				if autoDriveCount > 0 && finishReason != "tool_calls" {
					log.Warnf("trae executor stream: auto-drive exhausted after %d attempt(s), turn still ends without a tool call (text=%q)", autoDriveCount, strings.TrimSpace(fullAssistantContent.String()))
				}

				doneChunkJSON := helps.FormatOpenAIStreamChunk(compID, req.Model, "", "", finishReason)
				lineChunk := append([]byte("data: "), doneChunkJSON...)
				lineChunk = append(lineChunk, []byte("\n\n")...)

				chunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, currentPayload, bytes.Clone(lineChunk), &param, claudeInputTokens)
				for i := range chunks {
					select {
					case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
					case <-ctx.Done():
						return
					}
				}

				// Terminal [DONE]
				doneChunks := helps.TranslateStreamWithClaudeInputTokens(ctx, to, responseFormat, req.Model, originalPayload, currentPayload, []byte("data: [DONE]\n\n"), &param, claudeInputTokens)
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
		Headers: activeResp.Header.Clone(),
		Chunks:  out,
	}, nil
}

// CountTokens provides token counting for Trae.
func (e *TraeExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	// Trae counts can be wrapped via standard translator
	return cliproxyexecutor.Response{}, nil
}
