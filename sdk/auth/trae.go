package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	traeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/trae"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

var traeRefreshLead = 15 * time.Minute

// TraeAuthenticator implements authentication and discovery for Trae IDE credentials.
type TraeAuthenticator struct{}

// NewTraeAuthenticator constructs a new Trae authenticator.
func NewTraeAuthenticator() Authenticator {
	return &TraeAuthenticator{}
}

// Provider returns the provider key for Trae.
func (TraeAuthenticator) Provider() string {
	return "trae"
}

// RefreshLead returns the duration before token expiry when refresh should occur.
func (TraeAuthenticator) RefreshLead() *time.Duration {
	return &traeRefreshLead
}

// Login discovers and loads local Trae credentials from storage.json.
func (a TraeAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	fmt.Println("Searching for local Trae IDE credentials...")
	tokenStorage, err := traeauth.LoadAuthFromLocalTrae("", "")
	if err != nil {
		return nil, fmt.Errorf("trae: failed to discover local credentials: %w", err)
	}

	metadata := map[string]any{
		"type":            "trae",
		"access_token":    tokenStorage.AccessToken,
		"refresh_token":   tokenStorage.RefreshToken,
		"expired":         tokenStorage.Expired,
		"refresh_expired": tokenStorage.RefreshExpired,
		"device_id":       tokenStorage.DeviceID,
		"machine_id":      tokenStorage.MachineID,
		"user_id":         tokenStorage.UserID,
		"edition":         tokenStorage.Edition,
		"host":            tokenStorage.Host,
		"auth_host":       tokenStorage.AuthHost,
		"timestamp":       time.Now().UnixMilli(),
	}

	editionLabel := strings.ToUpper(tokenStorage.Edition)
	if editionLabel == "" {
		editionLabel = "CN"
	}

	fileName := fmt.Sprintf("trae-%s-%d.json", strings.ToLower(editionLabel), time.Now().UnixMilli())
	label := fmt.Sprintf("Trae %s (%s)", editionLabel, tokenStorage.UserID)
	if tokenStorage.UserID == "" {
		label = fmt.Sprintf("Trae %s User", editionLabel)
	}

	fmt.Printf("\nTrae authentication successful! (Edition: %s, UserID: %s)\n", editionLabel, tokenStorage.UserID)

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    label,
		Storage:  tokenStorage,
		Metadata: metadata,
	}, nil
}
