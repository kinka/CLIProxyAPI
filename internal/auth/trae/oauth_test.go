package trae

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGeneratePKCECodes(t *testing.T) {
	pkce, err := GeneratePKCECodes()
	if err != nil {
		t.Fatalf("GeneratePKCECodes failed: %v", err)
	}
	if len(pkce.CodeVerifier) < 43 {
		t.Fatalf("CodeVerifier too short: %q", pkce.CodeVerifier)
	}
	if len(pkce.CodeChallenge) < 43 {
		t.Fatalf("CodeChallenge too short: %q", pkce.CodeChallenge)
	}
}

func TestGenerateDeviceKeyPair(t *testing.T) {
	pemKey, err := GenerateDeviceKeyPair()
	if err != nil {
		t.Fatalf("GenerateDeviceKeyPair failed: %v", err)
	}
	if !strings.Contains(pemKey, "-----BEGIN PUBLIC KEY-----") || !strings.Contains(pemKey, "-----END PUBLIC KEY-----") {
		t.Fatalf("Invalid PEM public key output:\n%s", pemKey)
	}
}

func TestBuildAuthorizationURL(t *testing.T) {
	pkce, _ := GeneratePKCECodes()

	// 1. CN Edition
	cnURL, err := BuildAuthorizationURL(TraeAuthURLOptions{
		Edition:     "cn",
		CallbackURL: "http://127.0.0.1:54546/authorize",
		State:       "test-cn-state",
		PKCE:        pkce,
		MachineID:   "m-12345",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL (CN) failed: %v", err)
	}
	u, err := url.Parse(cnURL)
	if err != nil {
		t.Fatalf("Parse URL failed: %v", err)
	}
	if u.Host != "www.trae.cn" || u.Path != "/authorization" {
		t.Errorf("Unexpected host/path for CN: %s", cnURL)
	}
	q := u.Query()
	if q.Get("client_id") != DefaultOAuthClientID {
		t.Errorf("expected client_id %s, got %s", DefaultOAuthClientID, q.Get("client_id"))
	}
	if q.Get("code_challenge") != pkce.CodeChallenge {
		t.Errorf("expected code_challenge %s, got %s", pkce.CodeChallenge, q.Get("code_challenge"))
	}
	if q.Get("state") != "test-cn-state" {
		t.Errorf("expected state test-cn-state, got %s", q.Get("state"))
	}
	if q.Get("auth_callback_url") != "http://127.0.0.1:54546/authorize" {
		t.Errorf("unexpected callback url: %s", q.Get("auth_callback_url"))
	}

	// 2. SG Edition
	sgURL, err := BuildAuthorizationURL(TraeAuthURLOptions{
		Edition:     "sg",
		CallbackURL: "http://127.0.0.1:54546/authorize",
		State:       "test-sg-state",
		PKCE:        pkce,
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL (SG) failed: %v", err)
	}
	if !strings.HasPrefix(sgURL, "https://www.trae.ai/authorization?") {
		t.Errorf("unexpected SG url: %s", sgURL)
	}

	// 3. Enterprise Edition
	entURL, err := BuildAuthorizationURL(TraeAuthURLOptions{
		Edition:      "enterprise",
		ConsoleHost:  "https://console.enterprise.trae.cn",
		CallbackURL:  "http://127.0.0.1:54546/callback",
		State:        "test-ent-state",
		PKCE:         pkce,
		IsEnterprise: true,
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL (Enterprise) failed: %v", err)
	}
	if !strings.HasPrefix(entURL, "https://console.enterprise.trae.cn/authorization?") {
		t.Errorf("unexpected Enterprise url: %s", entURL)
	}
	uEnt, _ := url.Parse(entURL)
	if uEnt.Query().Get("scope") != "saas" {
		t.Errorf("expected scope saas, got %s", uEnt.Query().Get("scope"))
	}
}

func TestExchangeTokenByAuthCode(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/trae/api/v3/oauth/ExchangeToken" {
			http.NotFound(w, r)
			return
		}

		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["AuthCode"] != "valid-code" {
			http.Error(w, `{"code": 40001, "msg": "invalid code"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "success",
			"data": map[string]any{
				"token":              "mock-access-token-12345",
				"refresh_token":      "mock-refresh-token-67890",
				"expires_in":         2592000,
				"refresh_expires_in": 7776000,
				"user_id":            "user-88888",
				"user_region":        "CN",
			},
		})
	}))
	defer mockServer.Close()

	ctx := context.Background()
	storage, err := ExchangeTokenByAuthCode(
		ctx,
		mockServer.Client(),
		mockServer.URL,
		"valid-code",
		"test-verifier",
		"pem-key",
		"machine-1",
		"device-1",
		"3.3.67",
		"cn",
	)
	if err != nil {
		t.Fatalf("ExchangeTokenByAuthCode failed: %v", err)
	}

	if storage.AccessToken != "mock-access-token-12345" {
		t.Errorf("expected access token 'mock-access-token-12345', got %q", storage.AccessToken)
	}
	if storage.RefreshToken != "mock-refresh-token-67890" {
		t.Errorf("expected refresh token 'mock-refresh-token-67890', got %q", storage.RefreshToken)
	}
	if storage.UserID != "user-88888" {
		t.Errorf("expected user id 'user-88888', got %q", storage.UserID)
	}
}

func TestTraeOAuthServer(t *testing.T) {
	srv := NewTraeOAuthServer(54589)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start server failed: %v", err)
	}
	defer func() {
		_ = srv.Stop(context.Background())
	}()

	// Simulate callback request
	go func() {
		time.Sleep(50 * time.Millisecond)
		resp, err := http.Get("http://127.0.0.1:54589/callback?code=test-auth-code&state=my-state")
		if err != nil {
			t.Errorf("callback GET failed: %v", err)
			return
		}
		_ = resp.Body.Close()
	}()

	res, err := srv.WaitForCallback(2 * time.Second)
	if err != nil {
		t.Fatalf("WaitForCallback failed: %v", err)
	}
	if res.Code != "test-auth-code" {
		t.Errorf("expected code 'test-auth-code', got %q", res.Code)
	}
	if res.State != "my-state" {
		t.Errorf("expected state 'my-state', got %q", res.State)
	}
}

func TestParseEnterpriseCallback(t *testing.T) {
	rawURL := `http://127.0.0.1:8317/authorize?scope=saas&host=https%3A%2F%2Fconsole.enterprise.trae.cn&consoleHost=https%3A%2F%2Fconsole.enterprise.trae.cn&coreHost=https%3A%2F%2Fconsole.enterprise.trae.cn&isRedirect=true&loginTraceID=9dfb3b839f9ede128fa77bafe0d6b711&userJwt=%7B%22RefreshToken%22%3A%22DJvJ5SoUVByYeBKOoUFHvyQo4Lw17I8WoSy0VBdrYhw%3D.18d73bba2293d0c4%22%2C%22RefreshExpireAt%22%3A1797741047530%2C%22Token%22%3A%22mock-jwt-token%22%2C%22TokenExpireAt%22%3A1791174647537%2C%22TokenExpireDuration%22%3A1209600000%7D&userInfo=%7B%22UserInfo%22%3A%7B%22UserID%22%3A%22419608832%22%2C%22Name%22%3A%22%E9%BB%84%E9%92%A6%E4%BD%B3%22%2C%22Avatar%22%3A%22%22%2C%22Account%22%3A%22kinkabrain%40gmail.com%22%2C%22Password%22%3A%22%22%2C%22Email%22%3A%22kinkabrain%40gmail.com%22%2C%22UserStatus%22%3A1%2C%22RoleID%22%3A3%2C%22TenantID%22%3A%22275232256%22%7D%2C%22TenantInfoBase%22%3A%7B%22TenantID%22%3A275232256%2C%22TenantName%22%3A%22%E5%B9%BF%E5%8F%91%E8%AF%81%E5%88%B8%E8%82%A1%E4%BB%BD%E6%9C%89%E9%99%90%E5%85%AC%E5%8F%B8%22%7D%7D`

	storage, err := ParseEnterpriseCallback(rawURL, "m-id-1", "d-id-1")
	if err != nil {
		t.Fatalf("ParseEnterpriseCallback failed: %v", err)
	}
	if storage == nil {
		t.Fatalf("expected storage not nil")
	}
	if storage.AccessToken != "mock-jwt-token" {
		t.Errorf("expected access token 'mock-jwt-token', got %q", storage.AccessToken)
	}
	if storage.UserID != "419608832" {
		t.Errorf("expected user id '419608832', got %q", storage.UserID)
	}
	if storage.Edition != "enterprise" {
		t.Errorf("expected edition 'enterprise', got %q", storage.Edition)
	}
	if storage.Host != "https://console.enterprise.trae.cn" {
		t.Errorf("expected host https://console.enterprise.trae.cn, got %q", storage.Host)
	}
	if storage.Account["tenant_name"] != "广发证券股份有限公司" {
		t.Errorf("expected tenant name '广发证券股份有限公司', got %v", storage.Account["tenant_name"])
	}
}

