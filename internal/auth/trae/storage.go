package trae

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	AuthStorageKey = "iCubeAuthInfo://icube.cloudide"

	DefaultHostCN = "https://trae-api-cn.mchost.guru"
	DefaultHostSG = "https://coresg-normal.trae.ai"
	DefaultHostUS = "https://coreva-normal.trae.ai"
)

// DefaultDataDirForEdition returns the default configuration path for Trae CN or SG edition.
func DefaultDataDirForEdition(edition string) string {
	name := "Trae"
	if strings.EqualFold(edition, "cn") {
		name = "Trae CN"
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", name)
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData != "" {
			return filepath.Join(appData, name)
		}
		return filepath.Join(homeDir, "AppData", "Roaming", name)
	default: // linux and others
		configDir := os.Getenv("XDG_CONFIG_HOME")
		if configDir != "" {
			return filepath.Join(configDir, name)
		}
		return filepath.Join(homeDir, ".config", name)
	}
}

// StorageJSONPath returns the path to storage.json in the data directory.
func StorageJSONPath(dataDir string) string {
	return filepath.Join(dataDir, "User", "globalStorage", "storage.json")
}

// DetectEdition detects if CN or SG Trae edition is installed and more recently used.
func DetectEdition() string {
	if envEd := os.Getenv("TRAE_EDITION"); envEd != "" {
		return strings.ToLower(envEd)
	}

	cnPath := StorageJSONPath(DefaultDataDirForEdition("cn"))
	sgPath := StorageJSONPath(DefaultDataDirForEdition("sg"))

	cnStat, cnErr := os.Stat(cnPath)
	sgStat, sgErr := os.Stat(sgPath)

	if cnErr == nil && sgErr != nil {
		return "cn"
	}
	if cnErr != nil && sgErr == nil {
		return "sg"
	}
	if cnErr == nil && sgErr == nil {
		if cnStat.ModTime().After(sgStat.ModTime()) {
			return "cn"
		}
		return "sg"
	}
	return "cn"
}

// ReadStorageJSON loads and parses storage.json into a map.
func ReadStorageJSON(storagePath string) (map[string]any, error) {
	data, err := os.ReadFile(storagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage.json: %w", err)
	}
	var res map[string]any
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("failed to parse storage.json: %w", err)
	}
	return res, nil
}

type authPayload struct {
	Token            string         `json:"token"`
	RefreshToken     string         `json:"refreshToken"`
	ExpiredAt        string         `json:"expiredAt"`
	RefreshExpiredAt string         `json:"refreshExpiredAt"`
	TokenReleaseAt   string         `json:"tokenReleaseAt"`
	UserID           string         `json:"userId"`
	Host             string         `json:"host"`
	UserRegion       any            `json:"userRegion"`
	Account          map[string]any `json:"account"`
}

// LoadAuthFromLocalTrae attempts to discover and load Trae credentials from local storage.json.
func LoadAuthFromLocalTrae(dataDir string, edition string) (*TraeTokenStorage, error) {
	ed := edition
	if ed == "" {
		ed = DetectEdition()
	}

	editions := []string{ed}
	if strings.EqualFold(ed, "cn") {
		editions = append(editions, "sg")
	} else {
		editions = append(editions, "cn")
	}

	var lastErr error
	for _, currentEd := range editions {
		dir := dataDir
		if dir == "" {
			dir = DefaultDataDirForEdition(currentEd)
		}
		storagePath := StorageJSONPath(dir)
		storage, err := ReadStorageJSON(storagePath)
		if err != nil {
			lastErr = err
			continue
		}

		rawAuthVal, ok := storage[AuthStorageKey]
		if !ok {
			lastErr = fmt.Errorf("auth key %q not found in %s", AuthStorageKey, storagePath)
			continue
		}

		authStr, isStr := rawAuthVal.(string)
		if !isStr {
			lastErr = fmt.Errorf("auth key value is not a string in %s", storagePath)
			continue
		}

		trimmed := strings.TrimSpace(authStr)
		var authJSON []byte
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "\"") {
			// Plaintext (SG edition)
			if strings.HasPrefix(trimmed, "\"") {
				var unquoted string
				if err := json.Unmarshal([]byte(trimmed), &unquoted); err == nil {
					authJSON = []byte(unquoted)
				} else {
					authJSON = []byte(trimmed)
				}
			} else {
				authJSON = []byte(trimmed)
			}
		} else {
			// Encrypted (CN edition tc)
			decrypted, err := DecryptStorageValue(trimmed)
			if err != nil {
				lastErr = fmt.Errorf("failed to decrypt auth data for %s: %w", currentEd, err)
				continue
			}
			authJSON = decrypted
		}

		var payload authPayload
		if err := json.Unmarshal(authJSON, &payload); err != nil {
			lastErr = fmt.Errorf("failed to parse auth payload JSON for %s: %w", currentEd, err)
			continue
		}

		machineID, _ := storage["telemetry.machineId"].(string)
		sqmID, _ := storage["telemetry.sqmId"].(string)
		devDeviceID, _ := storage["telemetry.devDeviceId"].(string)

		regionStr := ""
		if payload.UserRegion != nil {
			if rMap, ok := payload.UserRegion.(map[string]any); ok {
				if r, ok := rMap["region"].(string); ok {
					regionStr = r
				}
			} else if rStr, ok := payload.UserRegion.(string); ok {
				regionStr = rStr
			}
		}

		apiHost := DefaultHostSG
		authHost := DefaultHostSG
		if strings.EqualFold(currentEd, "cn") {
			apiHost = DefaultHostCN
			authHost = DefaultHostCN
		} else if strings.EqualFold(regionStr, "US") {
			apiHost = DefaultHostUS
		}

		// Check enterprise boot config
		if boot, ok := payload.Account["saasBootConfig"].(map[string]any); ok {
			if aHost, ok := boot["apiHost"].(string); ok && aHost != "" {
				authHost = strings.TrimRight(aHost, "/")
			} else if cHost, ok := boot["consoleHost"].(string); ok && cHost != "" {
				authHost = strings.TrimRight(cHost, "/")
			}
		}

		return &TraeTokenStorage{
			AccessToken:    payload.Token,
			RefreshToken:   payload.RefreshToken,
			TokenType:      "Cloud-IDE-JWT",
			Expired:        payload.ExpiredAt,
			RefreshExpired: payload.RefreshExpiredAt,
			DeviceID:       HashDeviceID(machineID),
			MachineID:      machineID,
			DevDeviceID:    devDeviceID,
			SqmID:          sqmID,
			UserID:         payload.UserID,
			Edition:        currentEd,
			Host:           apiHost,
			AuthHost:       authHost,
			UserRegion:     regionStr,
			Account:        payload.Account,
			Type:           "trae",
		}, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no valid Trae auth found in local storage")
}
