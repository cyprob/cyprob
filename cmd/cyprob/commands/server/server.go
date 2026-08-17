package server

import (
	"github.com/spf13/cobra"
)

const cliExecutable = "server"

func NewCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   cliExecutable,
		Short: "Cyprob server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	command.SuggestionsMinimumDistance = 1

	// Subcommands
	command.AddCommand(newStartServerCommand())

	return command
}
