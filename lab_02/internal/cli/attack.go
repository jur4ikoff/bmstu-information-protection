package cli

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/ypopov2005/bmstu-information-protection/internal/enigma"
)

// newAttackCommand demonstrates a known-plaintext attack against one unknown
// plugboard pair. ZIP's usual 50 4b 03 04 prefix makes a convenient fragment.
func newAttackCommand() *cobra.Command {
	options := cryptOptions{}
	var knownHex string
	var offset int64
	command := &cobra.Command{
		Use:   "attack",
		Short: "Найти одну пару коммутационной панели по известному фрагменту",
		RunE: func(_ *cobra.Command, _ []string) error {
			if options.input == "" {
				return fmt.Errorf("--input is required")
			}
			if offset < 0 {
				return fmt.Errorf("--offset must not be negative")
			}
			known, err := hex.DecodeString(knownHex)
			if err != nil || len(known) == 0 {
				return fmt.Errorf("--known-hex must contain a non-empty even-length hexadecimal fragment")
			}
			config, err := enigma.LoadConfig(options.config)
			if err != nil {
				return err
			}
			if options.positions != "" {
				config.Positions = options.positions
			}
			if options.rotors != "" {
				config.Rotors = splitList(options.rotors)
			}
			if options.reflector != "" {
				config.Reflector = options.reflector
			}
			if options.plugboard != "" || len(config.Plugboard) != 0 {
				return fmt.Errorf("attack expects the unknown plugboard pair: omit --plugboard and plugboard in config")
			}
			ciphertext, err := readKnownCiphertext(options.input, offset, len(known))
			if err != nil {
				return err
			}
			found := 0
			for a := 0; a < 256; a++ {
				for b := a + 1; b < 256; b++ {
					candidate := config
					candidate.Plugboard = []string{fmt.Sprintf("%d:%d", a, b)}
					machine, err := enigma.NewConfigured(candidate)
					if err != nil {
						return err
					}
					machine.Advance(offset)
					trial := append([]byte(nil), known...)
					machine.Transform(trial)
					if string(trial) == string(ciphertext) {
						fmt.Printf("candidate plugboard pair: %d:%d\n", a, b)
						found++
					}
				}
			}
			if found == 0 {
				return fmt.Errorf("no one-pair solution found; check header, offset and rotor configuration")
			}
			return nil
		},
	}
	addCryptFlags(command, &options)
	command.Flags().StringVar(&knownHex, "known-hex", "504b0304", "Известный открытый фрагмент в hex (ZIP по умолчанию)")
	command.Flags().Int64Var(&offset, "offset", 0, "Смещение фрагмента в исходном архиве")
	return command
}

func readKnownCiphertext(path string, offset int64, length int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ciphertext: %w", err)
	}
	defer f.Close()
	// ENIGAR1 header has 36 bytes. The ciphertext begins immediately after it.
	if _, err := f.Seek(36+offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek ciphertext: %w", err)
	}
	result := make([]byte, length)
	if _, err := io.ReadFull(f, result); err != nil {
		return nil, fmt.Errorf("read known ciphertext: %w", err)
	}
	return result, nil
}
