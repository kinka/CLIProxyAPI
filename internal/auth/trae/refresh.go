package trae

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

const (
	DefaultOAuthClientID     = "ono9krqynydwx5"
	DefaultOAuthClientSecret = "-"
)

type exchangeTokenRequest struct {
	ClientID     string `json:"ClientID"`
	RefreshToken string `json:"RefreshToken"`
	ClientSecret string `json:"ClientSecret"`
	UserID       string `json:"UserID"`
}

type ExchangeTokenResponse struct {
	Token            string `json:"token"`
	RefreshToken     string `json:"refreshToken"`
	ExpiredAt        string `json:"expiredAt"`
	RefreshExpiredAt string `json:"refreshExpiredAt"`
	TokenReleaseAt   string `json:"tokenReleaseAt"`
}

// ExchangeToken requests a new access token using the refresh token.
func ExchangeToken(ctx context.Context, httpClient *http.Client, authHost, refreshToken string) (*ExchangeTokenResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("trae: empty refresh token")
	}

	host := authHost
	if host == "" {
		host = DefaultHostCN
	}
	host = strings.TrimRight(host, "/")
	endpoint := host + "/cloudide/api/v3/trae/oauth/ExchangeToken"

	clientID := os.Getenv("TRAE_OAUTH_CLIENT_ID")
	if clientID == "" {
		clientID = DefaultOAuthClientID
	}
	clientSecret := os.Getenv("TRAE_OAUTH_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = DefaultOAuthClientSecret
	}

	reqBody := exchangeTokenRequest{
		ClientID:     clientID,
		RefreshToken: refreshToken,
		ClientSecret: clientSecret,
		UserID:       "",
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("trae: failed to marshal exchange token request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("trae: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("trae: exchange token request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("trae: failed to read exchange token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("trae: exchange token error (%d): %s", resp.StatusCode, traeExchangeErrorDetail(respBytes))
	}

	result, err := parseExchangeTokenResponse(respBytes)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// parseExchangeTokenResponse accepts both the flat IDE payload
// ({token, refreshToken, expiredAt}) and the enterprise payload, which
// nests Token / RefreshToken under Data and sends expiries as unix
// milliseconds (RefreshExpireAt, TokenExpireAt).
func parseExchangeTokenResponse(body []byte) (*ExchangeTokenResponse, error) {
	parsed := gjson.ParseBytes(body)
	data := parsed.Get("Data")
	if !data.Exists() || data.Type == gjson.Null {
		data = parsed.Get("data")
	}
	if !data.Exists() || data.Type == gjson.Null {
		data = parsed
	}

	token := firstNonEmpty(
		data.Get("Token").String(),
		data.Get("token").String(),
		data.Get("access_token").String(),
	)
	if token == "" {
		detail := traeExchangeErrorDetail(body)
		if detail == "" {
			return nil, fmt.Errorf("trae: exchange token response missing token")
		}
		return nil, fmt.Errorf("trae: exchange token response missing token: %s", detail)
	}

	expired := traeTimeField(data, "TokenExpireAt", "expiredAt", "expired_at", "expiresAt")
	if expired == "" {
		expired = jwtExpRFC3339(token)
	}

	return &ExchangeTokenResponse{
		Token:        token,
		RefreshToken: firstNonEmpty(data.Get("RefreshToken").String(), data.Get("refreshToken").String(), data.Get("refresh_token").String()),
		ExpiredAt:    expired,
		RefreshExpiredAt: traeTimeField(data,
			"RefreshExpireAt", "refreshExpiredAt", "refresh_expired_at", "refreshExpiresAt"),
		TokenReleaseAt: firstNonEmpty(data.Get("tokenReleaseAt").String(), data.Get("TokenReleaseAt").String()),
	}, nil
}

func traeTimeField(data gjson.Result, keys ...string) string {
	for _, key := range keys {
		value := data.Get(key)
		if !value.Exists() || value.Type == gjson.Null {
			continue
		}
		if formatted := formatTraeTimestamp(value); formatted != "" {
			return formatted
		}
	}
	return ""
}

func formatTraeTimestamp(value gjson.Result) string {
	switch value.Type {
	case gjson.Number:
		return formatTraeUnix(value.Int())
	case gjson.String:
		text := strings.TrimSpace(value.String())
		if text == "" {
			return ""
		}
		if n, err := strconv.ParseInt(text, 10, 64); err == nil {
			return formatTraeUnix(n)
		}
		return text
	default:
		return ""
	}
}

func formatTraeUnix(n int64) string {
	if n <= 0 {
		return ""
	}
	var ts time.Time
	switch {
	case n >= 1_000_000_000_000:
		ts = time.UnixMilli(n)
	case n >= 1_000_000_000:
		ts = time.Unix(n, 0)
	default:
		return ""
	}
	return ts.UTC().Format(time.RFC3339)
}

func jwtExpRFC3339(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	switch exp := claims["exp"].(type) {
	case float64:
		if exp <= 0 {
			return ""
		}
		return time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
	default:
		return ""
	}
}

// traeExchangeErrorDetail returns a log-safe summary. The raw body is not
// included because a successful enterprise payload carries the new tokens.
func traeExchangeErrorDetail(body []byte) string {
	parsed := gjson.ParseBytes(body)
	return firstNonEmpty(parsed.Get("message").String(), parsed.Get("Message").String())
}
