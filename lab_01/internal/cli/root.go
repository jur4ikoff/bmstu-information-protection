package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Execute creates and runs the command-line interface.
func Execute() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "enigma",
		Short:         "Шифрование файлов машиной Enigma",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newEncryptCommand(), newDecryptCommand())
	return root
}
