package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	archivecrypt "github.com/ypopov2005/bmstu-information-protection/internal/archive"
	"github.com/ypopov2005/bmstu-information-protection/internal/enigma"
)

type cryptOptions struct {
	input, output, config, positions, rotors, reflector, plugboard string
	raw                                                            bool
}

func addCryptFlags(command *cobra.Command, options *cryptOptions) {
	command.Flags().StringVarP(&options.input, "input", "i", "", "Путь к ZIP/TAR архиву")
	command.Flags().StringVarP(&options.output, "output", "o", "", "Путь к результату")
	command.Flags().StringVar(&options.config, "config", "", "JSON-файл конфигурации Enigma")
	command.Flags().StringVarP(&options.positions, "positions", "p", "", "Позиции четырех роторов слева направо")
	command.Flags().StringVar(&options.rotors, "rotors", "", "Четыре ротора, например IV,II,I,III")
	command.Flags().StringVar(&options.reflector, "reflector", "", "Рефлектор A или B")
	command.Flags().StringVar(&options.plugboard, "plugboard", "", "Пары BYTE:BYTE через запятую")
	command.Flags().BoolVar(&options.raw, "raw", false, "Обработать произвольный поток без контейнера и HMAC")
}

func newCryptCommand(name string, decrypt bool) *cobra.Command {
	options := cryptOptions{}
	command := &cobra.Command{Use: name, Short: map[bool]string{false: "Зашифровать ZIP/TAR архив", true: "Расшифровать ZIP/TAR архив"}[decrypt], RunE: func(_ *cobra.Command, _ []string) error { return execute(options, decrypt) }}
	if !decrypt {
		command.Aliases = []string{"e"}
	} else {
		command.Aliases = []string{"d"}
	}
	addCryptFlags(command, &options)
	return command
}

func execute(options cryptOptions, decrypt bool) error {
	if options.input == "" || options.output == "" {
		return fmt.Errorf("--input and --output are required")
	}
	machine, err := makeMachine(options)
	if err != nil {
		return err
	}
	if options.raw {
		return transformRaw(options.input, options.output, machine)
	}
	if decrypt {
		return archivecrypt.Decrypt(options.input, options.output, machine)
	}
	return archivecrypt.Encrypt(options.input, options.output, machine)
}

func makeMachine(options cryptOptions) (*enigma.Enigma, error) {
	config, err := enigma.LoadConfig(options.config)
	if err != nil {
		return nil, fmt.Errorf("configure Enigma: %w", err)
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
	if options.plugboard != "" {
		config.Plugboard = splitList(options.plugboard)
	}
	machine, err := enigma.NewConfigured(config)
	if err != nil {
		return nil, fmt.Errorf("configure Enigma: %w", err)
	}
	return machine, nil
}

func splitList(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}
func transformRaw(inputPath, outputPath string, machine *enigma.Enigma) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer input.Close()
	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer output.Close()
	reader, writer := bufio.NewReader(input), bufio.NewWriter(output)
	buffer := make([]byte, 64*1024)
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			machine.Transform(buffer[:n])
			if _, err := writer.Write(buffer[:n]); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read input: %w", readErr)
		}
	}
	return writer.Flush()
}

func newEntriesCommand() *cobra.Command {
	options := cryptOptions{}
	var files string
	var decrypt bool
	command := &cobra.Command{Use: "entries", Short: "Потоково зашифровать выбранные записи внутри ZIP/TAR", RunE: func(_ *cobra.Command, _ []string) error {
		if options.input == "" || options.output == "" || (!decrypt && files == "") {
			return fmt.Errorf("--input and --output are required; --files is required for encryption")
		}
		machine, err := makeMachine(options)
		if err != nil {
			return err
		}
		return archivecrypt.TransformEntries(options.input, options.output, machine, decrypt, splitList(files))
	}}
	addCryptFlags(command, &options)
	command.Flags().StringVar(&files, "files", "", "Имена записей архива через запятую")
	command.Flags().BoolVarP(&decrypt, "decrypt", "d", false, "Расшифровать выбранные записи по манифесту")
	return command
}
