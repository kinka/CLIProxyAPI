package trae

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExchangeTokenEnterpriseDataWrapper(t *testing.T) {
	const exp int64 = 1791174647
	const refreshExpireAt int64 = 1798949747164
	token := testJWT(exp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cloudide/api/v3/trae/oauth/ExchangeToken" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"","Data":{"Token":%q,"RefreshToken":"rotated-refresh","RefreshExpireAt":%d}}`, token, refreshExpireAt)
	}))
	defer srv.Close()

	got, err := ExchangeToken(context.Background(), srv.Client(), srv.URL, "old-refresh")
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if got.Token != token {
		t.Fatalf("token = %q", got.Token)
	}
	if got.RefreshToken != "rotated-refresh" {
		t.Fatalf("refresh token = %q", got.RefreshToken)
	}
	wantExpired := time.Unix(exp, 0).UTC().Format(time.RFC3339)
	if got.ExpiredAt != wantExpired {
		t.Fatalf("expired = %q, want %q", got.ExpiredAt, wantExpired)
	}
	wantRefresh := time.UnixMilli(refreshExpireAt).UTC().Format(time.RFC3339)
	if got.RefreshExpiredAt != wantRefresh {
		t.Fatalf("refresh expired = %q, want %q", got.RefreshExpiredAt, wantRefresh)
	}
}

func TestExchangeTokenEnterpriseTokenExpireAtOverridesJWT(t *testing.T) {
	token := testJWT(1791174647)
	const tokenExpireAt int64 = 1792000000000
	body := fmt.Sprintf(`{"Data":{"Token":%q,"TokenExpireAt":%d,"RefreshExpireAt":"1798949747164"}}`, token, tokenExpireAt)

	got, err := parseExchangeTokenResponse([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := time.UnixMilli(tokenExpireAt).UTC().Format(time.RFC3339)
	if got.ExpiredAt != want {
		t.Fatalf("expired = %q, want %q", got.ExpiredAt, want)
	}
	wantRefresh := time.UnixMilli(1798949747164).UTC().Format(time.RFC3339)
	if got.RefreshExpiredAt != wantRefresh {
		t.Fatalf("refresh expired = %q, want %q", got.RefreshExpiredAt, wantRefresh)
	}
}

func TestExchangeTokenFlatPayload(t *testing.T) {
	body := []byte(`{"token":"flat-token","refreshToken":"flat-refresh","expiredAt":"2026-10-22T02:38:50Z","refreshExpiredAt":"2027-01-06T02:38:50Z"}`)
	got, err := parseExchangeTokenResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Token != "flat-token" || got.RefreshToken != "flat-refresh" {
		t.Fatalf("tokens = %+v", got)
	}
	if got.ExpiredAt != "2026-10-22T02:38:50Z" || got.RefreshExpiredAt != "2027-01-06T02:38:50Z" {
		t.Fatalf("expiries = %q %q", got.ExpiredAt, got.RefreshExpiredAt)
	}
}

func TestExchangeTokenMissingTokenDoesNotLeakBody(t *testing.T) {
	const secret = "live-access-token-should-not-appear"
	body := []byte(`{"message":"网络异常","Data":null,"note":"` + secret + `"}`)

	_, err := parseExchangeTokenResponse(body)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "网络异常") {
		t.Fatalf("error = %q, want message", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked body: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `{"message":"网络异常","Data":{"Token":%q,"RefreshToken":"rotated"}}`, secret)
	}))
	defer srv.Close()

	_, err = ExchangeToken(context.Background(), srv.Client(), srv.URL, "old-refresh")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "网络异常") || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "rotated") {
		t.Fatalf("error = %v", err)
	}
}

func TestFormatTraeUnixIgnoresSmallNumbers(t *testing.T) {
	if got := formatTraeUnix(14); got != "" {
		t.Fatalf("small number formatted as %q", got)
	}
	if got := formatTraeUnix(1_209_600); got != "" {
		t.Fatalf("ttl formatted as %q", got)
	}
}

func testJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp)))
	return header + "." + payload + ".sig"
}
