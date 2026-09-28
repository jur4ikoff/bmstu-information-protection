package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Execute() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{Use: "enigma", Short: "Потоковое шифрование ZIP/TAR архивов машиной Enigma", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(newCryptCommand("encrypt", false), newCryptCommand("decrypt", true), newEntriesCommand(), newAttackCommand())
	// OpenSSL-like short modes are supported without losing explicit subcommands.
	var encrypt, decrypt bool
	options := cryptOptions{}
	root.Flags().BoolVarP(&encrypt, "encrypt", "e", false, "Зашифровать архив")
	root.Flags().BoolVarP(&decrypt, "decrypt", "d", false, "Расшифровать архив")
	addCryptFlags(root, &options)
	root.RunE = func(_ *cobra.Command, _ []string) error {
		if encrypt == decrypt {
			return fmt.Errorf("specify exactly one of -e or -d, or use encrypt/decrypt subcommand")
		}
		return execute(options, decrypt)
	}
	return root
}
