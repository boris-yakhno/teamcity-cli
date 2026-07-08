package auth

import (
	"fmt"

	"github.com/JetBrains/teamcity-cli/api"
	"github.com/JetBrains/teamcity-cli/internal/cmdutil"
	"github.com/JetBrains/teamcity-cli/internal/completion"
	"github.com/JetBrains/teamcity-cli/internal/config"
	"github.com/spf13/cobra"
)

type authTokenOptions struct {
	serverURL string
}

func newAuthTokenCmd(f *cmdutil.Factory) *cobra.Command {
	opts := &authTokenOptions{}

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Print a stored TeamCity access token",
		Long: `Print a stored TeamCity access token to stdout.

This command is intended for local TeamCity clients that intentionally share
the CLI credential store.`,
		Example: `  teamcity auth token --server https://teamcity.example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuthToken(f, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.serverURL, "server", "s", "", "TeamCity server URL")
	_ = cmd.RegisterFlagCompletionFunc("server", completion.ConfiguredServers())

	return cmd
}

func runAuthToken(f *cmdutil.Factory, opts *authTokenOptions) error {
	serverURL := opts.serverURL
	if serverURL == "" {
		serverURL = config.GetServerURL()
	}
	if serverURL == "" {
		return api.RequiredFlag("server")
	}
	serverURL = config.NormalizeURL(serverURL)

	token, _, keyringErr := config.GetTokenForServer(serverURL)
	if token == "" {
		if keyringErr != nil {
			return fmt.Errorf("token for %s could not be retrieved: %w", serverURL, keyringErr)
		}
		return api.Validation(
			"token not found",
			fmt.Sprintf("Run 'teamcity auth login --server %s' to authenticate", serverURL),
		)
	}

	_, _ = fmt.Fprintln(f.Printer.Out, token)
	return nil
}
