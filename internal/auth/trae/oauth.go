package trae

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	log "github.com/sirupsen/logrus"
)

// PKCECodes holds the code verifier and challenge for OAuth 2.0 PKCE.
type PKCECodes struct {
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
}

// GeneratePKCECodes generates a 48-byte URL-safe base64 code verifier and S256 code challenge.
func GeneratePKCECodes() (*PKCECodes, error) {
	bytes := make([]byte, 48)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes for PKCE: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(bytes)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &PKCECodes{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
	}, nil
}

// GenerateDeviceKeyPair generates an EC P-256 key pair and returns the SubjectPublicKeyInfo in PEM format.
func GenerateDeviceKeyPair() (string, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate EC P-256 key pair: %w", err)
	}
	pubDer, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDer,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// TraeAuthURLOptions holds configuration parameters for building Trae OAuth authorization URLs.
type TraeAuthURLOptions struct {
	Edition      string     // "cn", "sg", "enterprise"
	ConsoleHost  string     // e.g. "https://console.enterprise.trae.cn" or custom enterprise console domain
	APIHost      string     // e.g. "https://trae-api-cn.mchost.guru"
	CallbackURL  string     // e.g. "http://127.0.0.1:54546/authorize"
	State        string     // OAuth state
	LoginTraceID string     // login trace ID (defaults to state or uuid)
	PKCE         *PKCECodes // PKCE verifier and challenge
	MachineID    string     // machine ID (UUID)
	DeviceID     string     // device ID (hashed machine ID)
	Scope        string     // "saas" or custom scope
	IsEnterprise bool       // whether enterprise edition
}

// BuildAuthorizationURL generates the full Trae browser authorization URL.
func BuildAuthorizationURL(opts TraeAuthURLOptions) (string, error) {
	if opts.PKCE == nil {
		return "", fmt.Errorf("pkce codes are required")
	}
	if opts.CallbackURL == "" {
		return "", fmt.Errorf("callback url is required")
	}

	machineID := strings.TrimSpace(opts.MachineID)
	if machineID == "" {
		machineID = uuid.New().String()
	}
	deviceID := strings.TrimSpace(opts.DeviceID)
	if deviceID == "" {
		deviceID = HashDeviceID(machineID)
	}

	edition := strings.ToLower(strings.TrimSpace(opts.Edition))
	if edition == "" {
		edition = "cn"
	}

	var baseAuthHost string
	pluginVersion := "3.3.67"

	if opts.IsEnterprise || edition == "enterprise" || opts.ConsoleHost != "" {
		cHost := strings.TrimSpace(opts.ConsoleHost)
		if cHost == "" {
			cHost = "https://console.enterprise.trae.cn"
		}
		if !strings.HasPrefix(cHost, "http://") && !strings.HasPrefix(cHost, "https://") {
			cHost = "https://" + cHost
		}
		baseAuthHost = strings.TrimRight(cHost, "/") + "/authorization"
	} else if edition == "sg" {
		baseAuthHost = "https://www.trae.ai/authorization"
		pluginVersion = "3.5.51"
	} else {
		baseAuthHost = "https://www.trae.cn/authorization"
		pluginVersion = "3.3.67"
	}

	clientID := os.Getenv("TRAE_OAUTH_CLIENT_ID")
	if clientID == "" {
		clientID = DefaultOAuthClientID
	}

	loginTraceID := strings.TrimSpace(opts.LoginTraceID)
	if loginTraceID == "" {
		if strings.TrimSpace(opts.State) != "" {
			loginTraceID = strings.TrimSpace(opts.State)
		} else {
			loginTraceID = uuid.New().String()
		}
	}

	callbackURL := strings.TrimSpace(opts.CallbackURL)
	if parsedCB, errCB := url.Parse(callbackURL); errCB == nil && parsedCB.Host != "" {
		parsedCB.RawQuery = ""
		parsedCB.Fragment = ""
		parsedCB.Path = "/authorize"
		callbackURL = parsedCB.String()
	}

	params := url.Values{}
	params.Set("login_version", "1")
	params.Set("auth_from", "trae")
	params.Set("login_channel", "native_ide")
	params.Set("plugin_version", pluginVersion)
	params.Set("auth_type", "local")
	params.Set("client_id", clientID)
	params.Set("redirect", "0")
	params.Set("login_trace_id", loginTraceID)
	params.Set("auth_callback_url", callbackURL)
	params.Set("machine_id", machineID)
	params.Set("device_id", deviceID)
	params.Set("x_device_id", deviceID)
	params.Set("x_machine_id", machineID)
	params.Set("code_challenge", opts.PKCE.CodeChallenge)
	params.Set("code_challenge_method", "S256")

	if opts.State != "" {
		params.Set("state", opts.State)
	}

	if opts.IsEnterprise || edition == "enterprise" || opts.Scope != "" {
		scope := opts.Scope
		if scope == "" {
			scope = "saas"
		}
		params.Set("scope", scope)
	}

	return fmt.Sprintf("%s?%s", baseAuthHost, params.Encode()), nil
}

// ExchangeTokenByAuthCode exchanges an authorization code for Trae access/refresh tokens.
func ExchangeTokenByAuthCode(
	ctx context.Context,
	httpClient *http.Client,
	apiHost string,
	code string,
	codeVerifier string,
	pemPublicKey string,
	machineID string,
	deviceID string,
	ideVersion string,
	edition string,
) (*TraeTokenStorage, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("trae: empty authorization code")
	}
	if strings.TrimSpace(codeVerifier) == "" {
		return nil, fmt.Errorf("trae: empty code verifier")
	}

	host := strings.TrimSpace(apiHost)
	if host == "" {
		if strings.EqualFold(edition, "sg") {
			host = DefaultHostSG
		} else {
			host = DefaultHostCN
		}
	}
	host = strings.TrimRight(host, "/")

	if machineID == "" {
		machineID = uuid.New().String()
	}
	if deviceID == "" {
		deviceID = HashDeviceID(machineID)
	}
	if pemPublicKey == "" {
		var errKey error
		pemPublicKey, errKey = GenerateDeviceKeyPair()
		if errKey != nil {
			log.Warnf("trae: failed to generate device key pair: %v", errKey)
		}
	}
	if ideVersion == "" {
		if strings.EqualFold(edition, "sg") {
			ideVersion = "3.5.51"
		} else {
			ideVersion = "3.3.67"
		}
	}

	clientID := os.Getenv("TRAE_OAUTH_CLIENT_ID")
	if clientID == "" {
		clientID = DefaultOAuthClientID
	}

	reqBody := map[string]any{
		"ClientID":     clientID,
		"AuthCode":     code,
		"CodeVerifier": codeVerifier,
		"DeviceInfo": map[string]any{
			"DevicePublicKey": pemPublicKey,
			"MachineID":       machineID,
			"DeviceID":        deviceID,
		},
		"IDEVersion": ideVersion,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("trae: failed to marshal exchange request: %w", err)
	}

	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	endpoints := []string{
		host + "/trae/api/v3/oauth/ExchangeToken",
		host + "/cloudide/api/v3/trae/oauth/ExchangeToken",
	}

	var lastErr error
	var respBytes []byte

	for _, endpoint := range endpoints {
		httpReq, errReq := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
		if errReq != nil {
			lastErr = errReq
			continue
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("x-app-id", "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8")
		httpReq.Header.Set("x-ide-version", ideVersion)
		httpReq.Header.Set("x-machine-id", machineID)
		httpReq.Header.Set("x-device-id", deviceID)
		httpReq.Header.Set("x-custom-trace-id", uuid.New().String())
		httpReq.Header.Set("X-Request-ID", uuid.New().String())

		resp, errDo := client.Do(httpReq)
		if errDo != nil {
			lastErr = errDo
			continue
		}

		respBytes, lastErr = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if lastErr != nil {
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			break
		}
		lastErr = fmt.Errorf("http %d: %s", resp.StatusCode, string(respBytes))
	}

	if lastErr != nil && len(respBytes) == 0 {
		return nil, fmt.Errorf("trae: exchange token request failed: %w", lastErr)
	}

	parsed := gjson.ParseBytes(respBytes)
	data := parsed.Get("data")
	if !data.Exists() {
		data = parsed
	}

	accessToken := data.Get("token").String()
	if accessToken == "" {
		accessToken = data.Get("access_token").String()
	}
	if accessToken == "" {
		return nil, fmt.Errorf("trae: exchange response missing access token: %s", string(respBytes))
	}

	refreshToken := data.Get("refresh_token").String()
	if refreshToken == "" {
		refreshToken = data.Get("refreshToken").String()
	}

	userID := data.Get("user_id").String()
	if userID == "" {
		userID = data.Get("userId").String()
	}

	userRegion := data.Get("user_region").String()
	if userRegion == "" {
		userRegion = data.Get("userRegion").String()
	}

	var expiredStr string
	if exp := data.Get("expires_in"); exp.Exists() && exp.Int() > 0 {
		expiredStr = time.Now().Add(time.Duration(exp.Int()) * time.Second).Format(time.RFC3339)
	} else if expAt := data.Get("expired_at"); expAt.Exists() {
		expiredStr = expAt.String()
	} else if expAtCamel := data.Get("expiredAt"); expAtCamel.Exists() {
		expiredStr = expAtCamel.String()
	}

	var refreshExpiredStr string
	if rexp := data.Get("refresh_expires_in"); rexp.Exists() && rexp.Int() > 0 {
		refreshExpiredStr = time.Now().Add(time.Duration(rexp.Int()) * time.Second).Format(time.RFC3339)
	} else if rexpAt := data.Get("refresh_expired_at"); rexpAt.Exists() {
		refreshExpiredStr = rexpAt.String()
	} else if rexpAtCamel := data.Get("refreshExpiredAt"); rexpAtCamel.Exists() {
		refreshExpiredStr = rexpAtCamel.String()
	}

	var accountMap map[string]any
	if acc := data.Get("account"); acc.Exists() && acc.IsObject() {
		_ = json.Unmarshal([]byte(acc.Raw), &accountMap)
	}

	ed := edition
	if ed == "" {
		if strings.EqualFold(userRegion, "CN") {
			ed = "cn"
		} else {
			ed = "sg"
		}
	}

	authHost := host
	if boot, ok := accountMap["saasBootConfig"].(map[string]any); ok {
		if aHost, ok := boot["apiHost"].(string); ok && aHost != "" {
			authHost = strings.TrimRight(aHost, "/")
		} else if cHost, ok := boot["consoleHost"].(string); ok && cHost != "" {
			authHost = strings.TrimRight(cHost, "/")
		}
	}

	return &TraeTokenStorage{
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		TokenType:      "Cloud-IDE-JWT",
		Expired:        expiredStr,
		RefreshExpired: refreshExpiredStr,
		DeviceID:       deviceID,
		MachineID:      machineID,
		UserID:         userID,
		Edition:        ed,
		Host:           host,
		AuthHost:       authHost,
		UserRegion:     userRegion,
		Account:        accountMap,
		Type:           "trae",
	}, nil
}

// GetUserInfo fetches current user info from Trae API.
func GetUserInfo(ctx context.Context, httpClient *http.Client, apiHost string, accessToken string) (map[string]any, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("trae: empty access token")
	}

	host := strings.TrimSpace(apiHost)
	if host == "" {
		host = DefaultHostCN
	}
	host = strings.TrimRight(host, "/")
	endpoint := host + "/cloudide/api/v3/trae/GetUserInfo"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("trae: failed to create get user info request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Cloud-IDE-JWT "+accessToken)
	req.Header.Set("X-Cloudide-Token", accessToken)

	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trae: get user info request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("trae: failed to read user info response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("trae: get user info returned %d: %s", resp.StatusCode, string(respBytes))
	}

	var res map[string]any
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("trae: failed to parse user info response: %w", err)
	}
	return res, nil
}

// TraeOAuthResult contains the authorization code result from the loopback server.
type TraeOAuthResult struct {
	Code  string
	State string
	Error string
}

// TraeOAuthServer provides a local HTTP server to receive the Trae OAuth authorization callback.
type TraeOAuthServer struct {
	server     *http.Server
	port       int
	resultChan chan *TraeOAuthResult
	errorChan  chan error
	mu         sync.Mutex
	running    bool
}

// NewTraeOAuthServer initializes a new Trae OAuth local callback server.
func NewTraeOAuthServer(port int) *TraeOAuthServer {
	if port <= 0 {
		port = 54546
	}
	return &TraeOAuthServer{
		port:       port,
		resultChan: make(chan *TraeOAuthResult, 1),
		errorChan:  make(chan error, 1),
	}
}

// Start starts the callback server.
func (s *TraeOAuthServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("trae oauth server is already running")
	}

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("port %d is already in use: %w", s.port, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", s.handleCallback)
	mux.HandleFunc("/auth/callback", s.handleCallback)
	mux.HandleFunc("/authorize", s.handleCallback)
	mux.HandleFunc("/oauth-callback", s.handleCallback)

	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	s.running = true

	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.errorChan <- fmt.Errorf("server failed: %w", err)
		}
	}()

	return nil
}

// Stop stops the callback server gracefully.
func (s *TraeOAuthServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.server == nil {
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	err := s.server.Shutdown(shutdownCtx)
	s.running = false
	s.server = nil
	return err
}

// WaitForCallback waits for the OAuth callback or timeout.
func (s *TraeOAuthServer) WaitForCallback(timeout time.Duration) (*TraeOAuthResult, error) {
	select {
	case res := <-s.resultChan:
		return res, nil
	case err := <-s.errorChan:
		return nil, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for Trae OAuth callback")
	}
}

func (s *TraeOAuthServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := strings.TrimSpace(firstNonEmpty(q.Get("code"), q.Get("AuthCode"), q.Get("auth_code")))
	if code == "" {
		if infoStr := q.Get("authCodeInfo"); infoStr != "" {
			var infoMap map[string]any
			if err := json.Unmarshal([]byte(infoStr), &infoMap); err == nil {
				for _, k := range []string{"AuthCode", "auth_code", "code", "Code"} {
					if v, ok := infoMap[k].(string); ok && v != "" {
						code = v
						break
					}
				}
			} else {
				code = infoStr
			}
		}
	}
	state := strings.TrimSpace(firstNonEmpty(q.Get("state"), q.Get("loginTraceID"), q.Get("login_trace_id")))
	errStr := strings.TrimSpace(firstNonEmpty(q.Get("error"), q.Get("error_msg"), q.Get("error_description")))

	if errStr != "" {
		s.resultChan <- &TraeOAuthResult{Error: errStr, State: state}
		http.Error(w, fmt.Sprintf("OAuth authorization error: %s", errStr), http.StatusBadRequest)
		return
	}

	if code == "" {
		s.resultChan <- &TraeOAuthResult{Error: "no_authorization_code", State: state}
		http.Error(w, "No authorization code found in callback", http.StatusBadRequest)
		return
	}

	s.resultChan <- &TraeOAuthResult{Code: code, State: state}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Trae Authentication Successful</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #0f172a; color: #f8fafc; }
        .card { background: #1e293b; padding: 2.5rem; border-radius: 1rem; box-shadow: 0 10px 25px rgba(0,0,0,0.5); text-align: center; max-width: 420px; }
        .icon { font-size: 3rem; margin-bottom: 1rem; }
        h1 { margin: 0 0 0.5rem 0; font-size: 1.5rem; }
        p { color: #94a3b8; font-size: 0.95rem; margin-bottom: 1.5rem; }
        .btn { background: #38bdf8; color: #0f172a; border: none; padding: 0.6rem 1.5rem; border-radius: 0.5rem; font-weight: 600; cursor: pointer; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🚀</div>
        <h1>Trae Authentication Successful!</h1>
        <p>You have successfully authenticated with Trae. You can close this browser window and return to the terminal.</p>
        <button class="btn" onclick="window.close()">Close Window</button>
    </div>
</body>
</html>`))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
