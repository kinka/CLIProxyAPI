package trae

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	log "github.com/sirupsen/logrus"
)

// TraeTokenStorage stores authentication token and environment information for Trae API.
type TraeTokenStorage struct {
	AccessToken    string         `json:"access_token"`
	RefreshToken   string         `json:"refresh_token,omitempty"`
	TokenType      string         `json:"token_type,omitempty"`
	Expired        string         `json:"expired,omitempty"`
	RefreshExpired string         `json:"refresh_expired,omitempty"`
	DeviceID       string         `json:"device_id,omitempty"`
	MachineID      string         `json:"machine_id,omitempty"`
	DevDeviceID    string         `json:"dev_device_id,omitempty"`
	SqmID          string         `json:"sqm_id,omitempty"`
	UserID         string         `json:"user_id,omitempty"`
	Edition        string         `json:"edition,omitempty"` // "cn", "sg", "manual"
	Host           string         `json:"host,omitempty"`
	AuthHost       string         `json:"auth_host,omitempty"`
	UserRegion     string         `json:"user_region,omitempty"`
	Account        map[string]any `json:"account,omitempty"`
	Type           string         `json:"type"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *TraeTokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

// SaveTokenToFile serializes the Trae token storage to a JSON file.
func (ts *TraeTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "trae"

	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return fmt.Errorf("failed to merge metadata: %w", errMerge)
	}

	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.Errorf("trae token storage: close token file error: %v", errClose)
		}
	}()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}
	return nil
}

// IsExpired checks if the access token has expired.
func (ts *TraeTokenStorage) IsExpired() bool {
	if ts.Expired == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, ts.Expired)
	if err != nil {
		return true
	}
	return time.Now().After(t)
}

// NeedsRefresh checks if the access token will expire within the given threshold.
func (ts *TraeTokenStorage) NeedsRefresh(threshold time.Duration) bool {
	if ts.Expired == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, ts.Expired)
	if err != nil {
		return true
	}
	return time.Now().Add(threshold).After(t)
}
