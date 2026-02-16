// pkg/cli/version.go
// Package cli provides CLI commands for the application.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	v "github.com/cyprob/cyprob/pkg/version"
)

func NewVersionCommand(cliExecutable string) *cobra.Command {
	var short bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			info := v.GetVersion()
			fmt.Printf("%s version: %s\n", cliExecutable, info.Version)
			if short {
				return
			}
			if info.Tag != "" {
				fmt.Printf("Tag: %s\n", info.Tag)
			}
			if info.Commit != "" {
				fmt.Printf("Commit: %s\n", info.Commit)
			}
			fmt.Printf("Build Date: %s\n", info.BuildDate)
			fmt.Printf("Go Version: %s\n", info.GoVersion)
			fmt.Printf("Compiler: %s\n", info.Compiler)
			fmt.Printf("Platform: %s\n", info.Platform)
		},
	}

	cmd.Flags().BoolVarP(&short, "short", "s", false, "Print only the version number")

	return cmd
}
