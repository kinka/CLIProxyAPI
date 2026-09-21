package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/trae"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const traeCallbackPort = 54546

func (h *Handler) traeCallbackURL() (string, error) {
	if h == nil || h.cfg == nil || h.cfg.Port <= 0 {
		return "", fmt.Errorf("server port is not configured")
	}
	return fmt.Sprintf("http://127.0.0.1:%d/authorize", h.cfg.Port), nil
}

// RequestTraeToken starts the Trae OAuth 2.0 PKCE authorization flow for WebUI and management clients.
func (h *Handler) RequestTraeToken(c *gin.Context) {
	edition := strings.ToLower(strings.TrimSpace(c.Query("edition")))
	if edition == "" {
		edition = "cn"
	}

	consoleHost := strings.TrimSpace(c.Query("console_host"))
	apiHost := strings.TrimSpace(c.Query("api_host"))
	isEnterprise := edition == "enterprise" || consoleHost != "" || c.Query("enterprise") == "true"

	var callbackURL string
	isWebUI := isWebUIRequest(c)

	if isWebUI {
		var errCallback error
		callbackURL, errCallback = h.traeCallbackURL()
		if errCallback != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "callback server unavailable"})
			return
		}
	} else {
		callbackURL = fmt.Sprintf("http://127.0.0.1:%d/authorize", traeCallbackPort)
	}

	pkceCodes, errPKCE := trae.GeneratePKCECodes()
	if errPKCE != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate PKCE codes"})
		return
	}

	pemPubKey, errKey := trae.GenerateDeviceKeyPair()
	if errKey != nil {
		log.Warnf("trae: failed to generate EC P-256 key pair: %v", errKey)
	}

	state, errState := misc.GenerateRandomState()
	if errState != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state parameter"})
		return
	}

	machineID := uuid.New().String()
	deviceID := trae.HashDeviceID(machineID)

	authURL, errURL := trae.BuildAuthorizationURL(trae.TraeAuthURLOptions{
		Edition:      edition,
		ConsoleHost:  consoleHost,
		APIHost:      apiHost,
		CallbackURL:  callbackURL,
		State:        state,
		LoginTraceID: state,
		PKCE:         pkceCodes,
		MachineID:    machineID,
		DeviceID:     deviceID,
		IsEnterprise: isEnterprise,
	})
	if errURL != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate authorization url"})
		return
	}

	RegisterOAuthSession(state, "trae")

	var forwarder *callbackForwarder
	if isWebUI {
		targetURL, errTarget := h.managementCallbackURL("/authorize")
		if errTarget == nil {
			forwarder, _ = startCallbackForwarder(traeCallbackPort, "trae", targetURL)
		}
	}

	ctx := PopulateAuthContext(context.Background(), c)
	authDir := h.cfg.AuthDir

	go func() {
		if forwarder != nil {
			defer stopCallbackForwarderInstance(traeCallbackPort, forwarder)
		}
		h.completeTraeOAuth(ctx, authDir, state, pkceCodes.CodeVerifier, pemPubKey, machineID, deviceID, edition, apiHost)
	}()

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"url":    authURL,
		"state":  state,
	})
}

func (h *Handler) completeTraeOAuth(
	ctx context.Context,
	authDir string,
	state string,
	codeVerifier string,
	pemPubKey string,
	machineID string,
	deviceID string,
	edition string,
	apiHost string,
) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	go watchOAuthSessionCancel(ctx, cancel, state, "trae")

	waitFile := filepath.Join(authDir, fmt.Sprintf(".oauth-trae-%s.oauth", state))
	defer func() {
		if errRemove := os.Remove(waitFile); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			log.Warn("failed to remove Trae OAuth callback file")
		}
	}()

	var code string
	var rawCallback string
	deadline := time.Now().Add(5 * time.Minute)

	for {
		if !IsOAuthSessionPending(state, "trae") {
			return
		}
		if time.Now().After(deadline) {
			SetOAuthSessionError(state, "Timeout waiting for OAuth callback")
			return
		}

		if data, errRead := os.ReadFile(waitFile); errRead == nil {
			var payload map[string]string
			if errUnmarshal := json.Unmarshal(data, &payload); errUnmarshal == nil {
				_ = os.Remove(waitFile)
				if errStr := payload["error"]; errStr != "" {
					SetOAuthSessionError(state, "Trae authorization denied: "+errStr)
					return
				}
				if payload["state"] != state {
					SetOAuthSessionError(state, "State code error")
					return
				}
				code = payload["code"]
				rawCallback = payload["raw_callback"]
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	var tokenStorage *trae.TraeTokenStorage
	if rawCallback != "" || strings.Contains(code, "userJwt") {
		candidate := rawCallback
		if candidate == "" {
			candidate = code
		}
		if entStorage, errEnt := trae.ParseEnterpriseCallback(candidate, machineID, deviceID); errEnt == nil && entStorage != nil {
			tokenStorage = entStorage
		}
	}

	if tokenStorage == nil {
		if strings.TrimSpace(code) == "" || code == "trae-enterprise-jwt" {
			SetOAuthSessionError(state, "No authorization code or credentials received")
			return
		}

		httpClient := util.SetProxy(&h.cfg.SDKConfig, &http.Client{Timeout: 30 * time.Second})

		ideVersion := "3.3.67"
		if strings.EqualFold(edition, "sg") {
			ideVersion = "3.5.51"
		}

		var errExchange error
		tokenStorage, errExchange = trae.ExchangeTokenByAuthCode(
			ctx,
			httpClient,
			apiHost,
			code,
			codeVerifier,
			pemPubKey,
			machineID,
			deviceID,
			ideVersion,
			edition,
		)
		if errExchange != nil {
			log.Errorf("Trae token exchange failed: %v", errExchange)
			SetOAuthSessionError(state, oauthSessionErrorWithCause("Failed to exchange authorization code for tokens", errExchange))
			return
		}
	}

	if errGuard := guardOAuthSessionPendingForSave(state, "trae"); errGuard != nil {
		return
	}

	editionLabel := strings.ToUpper(tokenStorage.Edition)
	if editionLabel == "" {
		editionLabel = "CN"
	}

	fileName := fmt.Sprintf("trae-%s-%d.json", strings.ToLower(editionLabel), time.Now().UnixMilli())
	label := fmt.Sprintf("Trae %s (%s)", editionLabel, tokenStorage.UserID)
	if tokenStorage.Account != nil {
		if tName, ok := tokenStorage.Account["tenant_name"].(string); ok && tName != "" {
			label = fmt.Sprintf("Trae %s (%s - %s)", editionLabel, tokenStorage.UserID, tName)
		}
	}
	if tokenStorage.UserID == "" {
		label = fmt.Sprintf("Trae %s User", editionLabel)
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

	record := &coreauth.Auth{
		ID:       fileName,
		Provider: "trae",
		FileName: fileName,
		Label:    label,
		Storage:  tokenStorage,
		Metadata: metadata,
	}

	savedPath, errSave := h.saveTokenRecord(ctx, record)
	if errSave != nil {
		SetOAuthSessionError(state, "Failed to save authentication tokens")
		log.Errorf("Failed to save Trae authentication tokens: %v", errSave)
		return
	}

	log.Infof("Trae authentication successful! Saved to %s", savedPath)
	CompleteOAuthSession(state)
}
