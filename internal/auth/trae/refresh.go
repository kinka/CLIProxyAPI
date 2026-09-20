package trae

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
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
		return nil, fmt.Errorf("trae: exchange token error (%d): %s", resp.StatusCode, string(respBytes))
	}

	var result ExchangeTokenResponse
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("trae: failed to parse exchange token response: %w", err)
	}

	if result.Token == "" {
		return nil, fmt.Errorf("trae: exchange token response missing token: %s", string(respBytes))
	}

	return &result, nil
}
