package auth

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/JetBrains/teamcity-cli/api"
	"github.com/JetBrains/teamcity-cli/internal/cmdutil"
	"github.com/JetBrains/teamcity-cli/internal/completion"
	"github.com/JetBrains/teamcity-cli/internal/config"
	"github.com/JetBrains/teamcity-cli/internal/output"
	"github.com/JetBrains/teamcity-cli/internal/version"
	"github.com/spf13/cobra"
)

type authStoreOptions struct {
	serverURL       string
	user            string
	expiresAt       string
	insecureStorage bool
	json            bool
}

type authStoreResult struct {
	Server               string `json:"server"`
	User                 string `json:"user"`
	Storage              string `json:"storage"`
	TokenExpiry          string `json:"token_expiry,omitempty"`
	DefaultServerUpdated bool   `json:"default_server_updated"`
}

func newAuthStoreCmd(f *cmdutil.Factory) *cobra.Command {
	opts := &authStoreOptions{}

	cmd := &cobra.Command{
		Use:   "store",
		Short: "Store a TeamCity access token from stdin",
		Long: `Store a TeamCity access token for a server.

The token is always read from stdin and is never accepted as a command-line
argument. Unlike auth login, this command does not change the default server.`,
		Example: `  printf '%s' "$TEAMCITY_TOKEN" | teamcity auth store --server https://teamcity.example.com
  printf '%s' "$TEAMCITY_TOKEN" | teamcity auth store --server https://teamcity.example.com --user john.doe --expires-at 2026-08-07T12:34:56Z`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuthStore(f, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.serverURL, "server", "s", "", "TeamCity server URL")
	cmd.Flags().StringVar(&opts.user, "user", "", "Username for the token; discovered by validating the token if omitted")
	cmd.Flags().StringVar(&opts.expiresAt, "expires-at", "", "Token expiry timestamp in RFC3339 format")
	cmd.Flags().BoolVar(&opts.insecureStorage, "insecure-storage", false, "Store token in plain text config file instead of system keyring")
	cmd.Flags().BoolVar(&opts.json, "json", false, "Output as JSON")

	_ = cmd.RegisterFlagCompletionFunc("server", completion.ConfiguredServers())

	return cmd
}

func runAuthStore(f *cmdutil.Factory, opts *authStoreOptions) error {
	if opts.serverURL == "" {
		return api.RequiredFlag("server")
	}
	serverURL := config.NormalizeURL(opts.serverURL)

	token, err := readTokenFromStdin(f.IOStreams.In)
	if err != nil {
		return err
	}

	expiresAt := opts.expiresAt
	if expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return api.Validation(
				"invalid --expires-at value",
				"Use RFC3339 format, for example 2026-08-07T12:34:56Z",
			)
		}
		expiresAt = parsed.Format(time.RFC3339)
	}

	user := opts.user
	if user == "" {
		currentUser, err := api.NewClient(serverURL, token,
			api.WithDebugFunc(f.Printer.Debug),
			api.WithVersion(version.String()),
		).WithContext(f.Context()).GetCurrentUser()
		if err != nil {
			return fmt.Errorf("failed to validate token and discover user: %w", err)
		}
		user = currentUser.Username
	}

	insecureFallback, err := config.StoreServerWithKeyring(serverURL, token, user, expiresAt, opts.insecureStorage)
	if err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	storage := "keyring"
	if insecureFallback {
		storage = "config"
	}

	result := authStoreResult{
		Server:               serverURL,
		User:                 user,
		Storage:              storage,
		TokenExpiry:          expiresAt,
		DefaultServerUpdated: false,
	}
	if opts.json {
		return f.Printer.PrintJSON(result)
	}

	f.Printer.Success("Stored token for %s as %s", output.Cyan(serverURL), output.Cyan(user))
	if insecureFallback {
		f.Printer.Warn("Token stored in plain text at %s", config.ConfigPath())
	} else {
		f.Printer.Success("Token stored in system keyring")
	}
	return nil
}

func readTokenFromStdin(r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read token from stdin: %w", err)
	}
	token := strings.TrimRight(string(data), "\r\n")
	if token == "" {
		return "", api.Validation(
			"token must be provided on stdin",
			"Pass the token through stdin; it is never accepted as a command-line argument",
		)
	}
	return token, nil
}
