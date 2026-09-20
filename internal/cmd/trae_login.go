package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	log "github.com/sirupsen/logrus"
)

// DoTraeLogin triggers the interactive OAuth PKCE or local import flow for Trae and saves tokens.
func DoTraeLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	promptFn := options.Prompt
	if promptFn == nil {
		promptFn = defaultProjectPrompt()
	}

	metadata := map[string]string{}

	if promptFn != nil {
		fmt.Println("\nSelect Trae authentication method:")
		fmt.Println("  1) Trae CN - China Personal Edition (Browser OAuth PKCE)")
		fmt.Println("  2) Trae SG - Global Personal Edition (Browser OAuth PKCE)")
		fmt.Println("  3) Trae Enterprise / SaaS (Browser OAuth PKCE)")
		fmt.Println("  4) Import credentials from local Trae IDE installation")

		choice, _ := promptFn("Enter choice [1-4] (default 1): ")
		choice = strings.TrimSpace(choice)

		switch choice {
		case "2", "sg", "global":
			metadata["edition"] = "sg"
		case "3", "enterprise", "saas":
			metadata["edition"] = "enterprise"
			metadata["is_enterprise"] = "true"
			consoleHost, _ := promptFn("Enter Enterprise Console Domain (default https://console.enterprise.trae.cn): ")
			consoleHost = strings.TrimSpace(consoleHost)
			if consoleHost != "" {
				metadata["console_host"] = consoleHost
			}
		case "4", "local", "import":
			metadata["mode"] = "local"
		default:
			metadata["edition"] = "cn"
		}
	} else {
		metadata["edition"] = "cn"
	}

	manager := newAuthManager()
	authOpts := &sdkAuth.LoginOptions{
		NoBrowser:    options.NoBrowser,
		CallbackPort: options.CallbackPort,
		Metadata:     metadata,
		Prompt:       promptFn,
	}

	record, savedPath, err := manager.Login(context.Background(), "trae", cfg, authOpts)
	if err != nil {
		log.Errorf("Trae authentication failed: %v", err)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}
	if record != nil && record.Label != "" {
		fmt.Printf("Authenticated as %s\n", record.Label)
	}
	fmt.Println("Trae authentication successful!")
}
