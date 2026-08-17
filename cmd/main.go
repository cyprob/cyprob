package main

import (
	"errors"
	"fmt"
	"os"

	cli "github.com/cyprob/cyprob/cmd/cyprob/commands"
	"github.com/cyprob/cyprob/pkg/plugin"
)

// main initializes the CLI application by determining the executable name and selecting
// the appropriate command to execute. It checks the executable name from the environment
// or the current process, then switches between available CLI commands (cyprob or cyprob-server).
// If the command execution fails, the application exits with an appropriate status code based on error type.
//
// Exit codes (as defined in ADR-0001):
//   - 0: Success
//   - 1: General error (default)
//   - 2: Invalid usage/input (plugin errors: ErrInvalidInput, ErrInvalidCategory, ErrInvalidPluginID)
//   - 4: Not found (plugin errors: ErrPluginNotFound, ErrPluginNotInstalled, ErrNoPluginsFound)
//   - 7: Service unavailable (plugin errors: ErrSourceNotAvailable, ErrUnavailable)
//   - 8: Partial failure (plugin errors: ErrPartialFailure)
func main() {
	command := cli.NewCommand()

	err := command.Execute()
	if err != nil {
		// Cobra is silenced so that a failure a command already summarized is
		// not stated twice. Everything it has NOT shown — an unknown flag, a
		// wrong argument count, a bad config file — is printed here, otherwise
		// the process would exit non-zero saying nothing at all.
		if !cli.IsAlreadyReported(err) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		// Determine exit code based on error type
		exitCode := getExitCode(err)
		os.Exit(exitCode)
	}
}

// getExitCode determines the appropriate exit code for an error.
// It checks if the error is a plugin service error and uses plugin.ExitCode() for mapping.
// Otherwise, it returns 1 (general error).
func getExitCode(err error) int {
	// Check if it's a plugin error using errors.Is
	if isPluginError(err) {
		return plugin.ExitCode(err)
	}

	// Default to general error
	return 1
}

// isPluginError checks if the error is a plugin service error
func isPluginError(err error) bool {
	return errors.Is(err, plugin.ErrPluginNotFound) ||
		errors.Is(err, plugin.ErrPluginNotInstalled) ||
		errors.Is(err, plugin.ErrNoPluginsFound) ||
		errors.Is(err, plugin.ErrInvalidInput) ||
		errors.Is(err, plugin.ErrInvalidCategory) ||
		errors.Is(err, plugin.ErrInvalidPluginID) ||
		errors.Is(err, plugin.ErrSourceNotAvailable) ||
		errors.Is(err, plugin.ErrUnavailable) ||
		errors.Is(err, plugin.ErrPluginAlreadyInstalled) ||
		errors.Is(err, plugin.ErrConflict) ||
		errors.Is(err, plugin.ErrPartialFailure) ||
		errors.Is(err, plugin.ErrChecksumMismatch)
}
