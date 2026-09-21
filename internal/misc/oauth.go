package misc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// GenerateRandomState generates a cryptographically secure random state parameter
// for OAuth2 flows to prevent CSRF attacks.
//
// Returns:
//   - string: A hexadecimal encoded random state string
//   - error: An error if the random generation fails, nil otherwise
func GenerateRandomState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// OAuthCallback captures the parsed OAuth callback parameters.
type OAuthCallback struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
}

// AsyncPrompt runs a prompt function in a goroutine and returns channels for
// the result. The returned channels are buffered (size 1) so the goroutine can
// complete even if the caller abandons the channels.
func AsyncPrompt(promptFn func(string) (string, error), message string) (<-chan string, <-chan error) {
	inputCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		input, err := promptFn(message)
		if err != nil {
			errCh <- err
			return
		}
		inputCh <- input
	}()
	return inputCh, errCh
}

// ParseOAuthCallback extracts OAuth parameters from a callback URL.
// It returns nil when the input is empty.
func ParseOAuthCallback(input string) (*OAuthCallback, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, nil
	}

	candidate := trimmed
	if !strings.Contains(candidate, "://") {
		if strings.HasPrefix(candidate, "?") {
			candidate = "http://localhost" + candidate
		} else if strings.ContainsAny(candidate, "/?#") || strings.Contains(candidate, ":") {
			candidate = "http://" + candidate
		} else if strings.Contains(candidate, "=") {
			candidate = "http://localhost/?" + candidate
		} else {
			return nil, fmt.Errorf("invalid callback URL")
		}
	}

	parsedURL, err := url.Parse(candidate)
	if err != nil {
		return nil, err
	}

	query := parsedURL.Query()
	code := strings.TrimSpace(query.Get("code"))
	if code == "" {
		code = strings.TrimSpace(firstNonEmpty(query.Get("AuthCode"), query.Get("auth_code")))
	}
	if code == "" {
		if infoStr := query.Get("authCodeInfo"); infoStr != "" {
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
	if code == "" && query.Get("userJwt") != "" {
		code = "trae-enterprise-jwt"
	}
	if code == "" && query.Get("data") != "" && query.Get("scope") == "saas" {
		code = query.Get("data")
	}
	state := strings.TrimSpace(query.Get("state"))
	if state == "" {
		state = strings.TrimSpace(firstNonEmpty(query.Get("loginTraceID"), query.Get("login_trace_id")))
	}
	errCode := strings.TrimSpace(query.Get("error"))
	if errCode == "" {
		errCode = strings.TrimSpace(query.Get("error_msg"))
	}
	errDesc := strings.TrimSpace(query.Get("error_description"))

	if parsedURL.Fragment != "" {
		if fragQuery, errFrag := url.ParseQuery(parsedURL.Fragment); errFrag == nil {
			if code == "" {
				code = strings.TrimSpace(fragQuery.Get("code"))
			}
			if state == "" {
				state = strings.TrimSpace(fragQuery.Get("state"))
			}
			if errCode == "" {
				errCode = strings.TrimSpace(fragQuery.Get("error"))
			}
			if errDesc == "" {
				errDesc = strings.TrimSpace(fragQuery.Get("error_description"))
			}
		}
	}

	if code != "" && state == "" && strings.Contains(code, "#") {
		parts := strings.SplitN(code, "#", 2)
		code = parts[0]
		state = parts[1]
	}

	if errCode == "" && errDesc != "" {
		errCode = errDesc
		errDesc = ""
	}

	if code == "" && errCode == "" {
		return nil, fmt.Errorf("callback URL missing code")
	}

	return &OAuthCallback{
		Code:             code,
		State:            state,
		Error:            errCode,
		ErrorDescription: errDesc,
	}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
