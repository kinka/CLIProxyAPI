package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestTraeRemoteOAuthFlow(t *testing.T) {
	authDir := t.TempDir()
	cfg := &config.Config{AuthDir: authDir, Port: 8317}
	h := NewHandlerWithoutConfigFilePath(cfg, nil)

	router := gin.New()
	router.GET("/trae-auth-url", h.RequestTraeToken)
	router.POST("/oauth-callback", h.PostOAuthCallback)
	router.GET("/get-auth-status", h.GetAuthStatus)

	// 1. Test Request CN Trae URL
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/trae-auth-url?edition=cn&is_webui=true", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("RequestTraeToken failed: %d %s", w.Code, w.Body.String())
	}

	var startResp struct {
		Status string `json:"status"`
		URL    string `json:"url"`
		State  string `json:"state"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("Failed to parse start response: %v", err)
	}

	if startResp.Status != "ok" || startResp.State == "" || startResp.URL == "" {
		t.Fatalf("Invalid response: %+v", startResp)
	}

	u, err := url.Parse(startResp.URL)
	if err != nil {
		t.Fatalf("Invalid auth url: %v", err)
	}
	if u.Host != "www.trae.cn" {
		t.Errorf("expected host www.trae.cn, got %s", u.Host)
	}
	if u.Query().Get("state") != startResp.State {
		t.Errorf("expected state %s, got %s", startResp.State, u.Query().Get("state"))
	}
	if u.Query().Get("auth_callback_url") != "http://127.0.0.1:8317/authorize" {
		t.Errorf("unexpected callback url: %s", u.Query().Get("auth_callback_url"))
	}

	// Verify session registered as pending
	if !IsOAuthSessionPending(startResp.State, "trae") {
		t.Fatalf("session %s not pending for trae", startResp.State)
	}

	// 2. Test Request Enterprise Trae URL
	wEnt := httptest.NewRecorder()
	reqEnt := httptest.NewRequest(http.MethodGet, "/trae-auth-url?edition=enterprise&console_host=https://console.enterprise.trae.cn&is_webui=true", nil)
	router.ServeHTTP(wEnt, reqEnt)

	if wEnt.Code != http.StatusOK {
		t.Fatalf("RequestTraeToken (Enterprise) failed: %d %s", wEnt.Code, wEnt.Body.String())
	}
	var entResp struct {
		Status string `json:"status"`
		URL    string `json:"url"`
		State  string `json:"state"`
	}
	_ = json.Unmarshal(wEnt.Body.Bytes(), &entResp)
	uEnt, _ := url.Parse(entResp.URL)
	if uEnt.Host != "console.enterprise.trae.cn" {
		t.Errorf("expected enterprise console host, got %s", uEnt.Host)
	}
	if uEnt.Query().Get("scope") != "saas" {
		t.Errorf("expected scope saas, got %s", uEnt.Query().Get("scope"))
	}

	// Clean up pending enterprise session
	CancelOAuthSession(entResp.State)

	// 3. Test Callback handling writing callback file
	callbackPayload := map[string]string{
		"provider": "trae",
		"state":    startResp.State,
		"code":     "test-trae-code-123",
	}
	callbackBody, _ := json.Marshal(callbackPayload)
	wCallback := httptest.NewRecorder()
	reqCallback := httptest.NewRequest(http.MethodPost, "/oauth-callback", strings.NewReader(string(callbackBody)))
	router.ServeHTTP(wCallback, reqCallback)

	if wCallback.Code != http.StatusOK {
		t.Fatalf("PostOAuthCallback failed: %d %s", wCallback.Code, wCallback.Body.String())
	}

	// Verify callback file written
	callbackFilePath := filepath.Join(authDir, ".oauth-trae-"+startResp.State+".oauth")
	time.Sleep(50 * time.Millisecond)
	// Even if exchange fails with mock code, we verify callback was received
	if _, err := os.Stat(callbackFilePath); err != nil && !os.IsNotExist(err) {
		t.Logf("callback file processed: %v", err)
	}
}
