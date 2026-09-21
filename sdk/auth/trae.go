package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	traeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/trae"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var traeRefreshLead = 15 * time.Minute

// TraeAuthenticator implements authentication and OAuth login for Trae IDE credentials.
type TraeAuthenticator struct {
	CallbackPort int
}

// NewTraeAuthenticator constructs a new Trae authenticator.
func NewTraeAuthenticator() *TraeAuthenticator {
	return &TraeAuthenticator{CallbackPort: 54546}
}

// Provider returns the provider key for Trae.
func (TraeAuthenticator) Provider() string {
	return "trae"
}

// RefreshLead returns the duration before token expiry when refresh should occur.
func (TraeAuthenticator) RefreshLead() *time.Duration {
	return &traeRefreshLead
}

// Login discovers local Trae credentials or performs OAuth 2.0 PKCE browser authentication.
func (a *TraeAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	mode := ""
	if opts.Metadata != nil {
		mode = strings.ToLower(strings.TrimSpace(opts.Metadata["mode"]))
	}

	// 1. Local Storage Discovery Mode
	if mode == "local" || (opts.Metadata != nil && opts.Metadata["import_local"] == "true") {
		fmt.Println("Searching for local Trae IDE credentials...")
		edition := ""
		if opts.Metadata != nil {
			edition = opts.Metadata["edition"]
		}
		tokenStorage, err := traeauth.LoadAuthFromLocalTrae("", edition)
		if err != nil {
			return nil, fmt.Errorf("trae: failed to discover local credentials: %w", err)
		}

		return a.buildAuthRecord(tokenStorage)
	}

	// 2. Browser OAuth 2.0 PKCE Flow
	callbackPort := a.CallbackPort
	if opts.CallbackPort > 0 {
		callbackPort = opts.CallbackPort
	}

	pkceCodes, err := traeauth.GeneratePKCECodes()
	if err != nil {
		return nil, fmt.Errorf("trae pkce generation failed: %w", err)
	}

	pemPubKey, err := traeauth.GenerateDeviceKeyPair()
	if err != nil {
		log.Warnf("trae: device key generation failed: %v", err)
	}

	state, err := misc.GenerateRandomState()
	if err != nil {
		return nil, fmt.Errorf("trae state generation failed: %w", err)
	}

	oauthServer := traeauth.NewTraeOAuthServer(callbackPort)
	if err = oauthServer.Start(); err != nil {
		return nil, fmt.Errorf("trae oauth callback server failed to start on port %d: %w", callbackPort, err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if stopErr := oauthServer.Stop(stopCtx); stopErr != nil {
			log.Warnf("trae oauth server stop error: %v", stopErr)
		}
	}()

	edition := "cn"
	consoleHost := ""
	apiHost := ""
	isEnterprise := false

	if opts.Metadata != nil {
		if ed := strings.ToLower(strings.TrimSpace(opts.Metadata["edition"])); ed != "" {
			edition = ed
		}
		consoleHost = strings.TrimSpace(opts.Metadata["console_host"])
		apiHost = strings.TrimSpace(opts.Metadata["api_host"])
		if opts.Metadata["is_enterprise"] == "true" || edition == "enterprise" || consoleHost != "" {
			isEnterprise = true
			if edition == "" {
				edition = "enterprise"
			}
		}
	}

	machineID := uuid.New().String()
	deviceID := traeauth.HashDeviceID(machineID)
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/authorize", callbackPort)

	authURL, err := traeauth.BuildAuthorizationURL(traeauth.TraeAuthURLOptions{
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
	if err != nil {
		return nil, fmt.Errorf("trae authorization url generation failed: %w", err)
	}

	editionDisplayName := "Trae CN"
	if isEnterprise {
		editionDisplayName = "Trae Enterprise"
	} else if strings.EqualFold(edition, "sg") {
		editionDisplayName = "Trae Global (SG)"
	}

	if !opts.NoBrowser {
		fmt.Printf("Opening browser for %s authentication...\n", editionDisplayName)
		if !browser.IsAvailable() {
			log.Warn("No browser available; please open the URL manually")
			util.PrintSSHTunnelInstructions(callbackPort)
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		} else if err = browser.OpenURL(authURL); err != nil {
			log.Warnf("Failed to open browser automatically: %v", err)
			util.PrintSSHTunnelInstructions(callbackPort)
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		}
	} else {
		util.PrintSSHTunnelInstructions(callbackPort)
		fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
	}

	fmt.Printf("Waiting for %s authentication callback...\n", editionDisplayName)

	callbackCh := make(chan *traeauth.TraeOAuthResult, 1)
	callbackErrCh := make(chan error, 1)

	go func() {
		res, errWait := oauthServer.WaitForCallback(5 * time.Minute)
		if errWait != nil {
			callbackErrCh <- errWait
			return
		}
		callbackCh <- res
	}()

	var result *traeauth.TraeOAuthResult
	var manualPromptTimer *time.Timer
	var manualPromptC <-chan time.Time
	if opts.Prompt != nil {
		manualPromptTimer = time.NewTimer(15 * time.Second)
		manualPromptC = manualPromptTimer.C
		defer manualPromptTimer.Stop()
	}

	var manualInputCh <-chan string
	var manualInputErrCh <-chan error

waitForCallback:
	for {
		select {
		case result = <-callbackCh:
			break waitForCallback
		case err = <-callbackErrCh:
			return nil, fmt.Errorf("trae authentication timed out or failed: %w", err)
		case <-manualPromptC:
			manualPromptC = nil
			if manualPromptTimer != nil {
				manualPromptTimer.Stop()
			}
			select {
			case result = <-callbackCh:
				break waitForCallback
			case err = <-callbackErrCh:
				return nil, fmt.Errorf("trae authentication timed out or failed: %w", err)
			default:
			}
			manualInputCh, manualInputErrCh = misc.AsyncPrompt(opts.Prompt, "Paste the Trae callback URL (or press Enter to keep waiting): ")
			continue
		case input := <-manualInputCh:
			manualInputCh = nil
			manualInputErrCh = nil
			parsed, errParse := misc.ParseOAuthCallback(input)
			if errParse != nil {
				return nil, errParse
			}
			if parsed == nil {
				continue
			}
			result = &traeauth.TraeOAuthResult{
				Code:  parsed.Code,
				State: parsed.State,
				Error: parsed.Error,
			}
			break waitForCallback
		case errManual := <-manualInputErrCh:
			return nil, errManual
		}
	}

	if result.Error != "" {
		return nil, fmt.Errorf("trae authorization error: %s", result.Error)
	}

	if result.State != "" && result.State != state {
		return nil, fmt.Errorf("trae state mismatch: expected %s, got %s", state, result.State)
	}

	fmt.Println("Trae authorization code received; exchanging for tokens...")

	httpClient := util.SetProxy(&cfg.SDKConfig, &http.Client{Timeout: 30 * time.Second})

	ideVersion := "3.3.67"
	if strings.EqualFold(edition, "sg") {
		ideVersion = "3.5.51"
	}

	tokenStorage, err := traeauth.ExchangeTokenByAuthCode(
		ctx,
		httpClient,
		apiHost,
		result.Code,
		pkceCodes.CodeVerifier,
		pemPubKey,
		machineID,
		deviceID,
		ideVersion,
		edition,
	)
	if err != nil {
		return nil, fmt.Errorf("trae token exchange failed: %w", err)
	}

	return a.buildAuthRecord(tokenStorage)
}

func (a *TraeAuthenticator) buildAuthRecord(tokenStorage *traeauth.TraeTokenStorage) (*coreauth.Auth, error) {
	if tokenStorage == nil {
		return nil, fmt.Errorf("trae: empty token storage")
	}

	editionLabel := strings.ToUpper(tokenStorage.Edition)
	if editionLabel == "" {
		editionLabel = "CN"
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
