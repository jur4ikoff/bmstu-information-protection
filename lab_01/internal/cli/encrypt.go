package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/ypopov2005/bmstu-information-protection/internal/enigma"
)

type encryptOptions struct {
	input     string
	output    string
	positions string
}

func newEncryptCommand() *cobra.Command {
	options := encryptOptions{}
	command := &cobra.Command{
		Use:   "encrypt",
		Short: "Зашифровать входной файл",
		RunE: func(_ *cobra.Command, _ []string) error {
			return execute(options)
		},
	}

	command.Flags().StringVarP(&options.input, "input", "i", "input.txt", "Путь к входному файлу")
	command.Flags().StringVarP(&options.output, "output", "o", "output.txt", "Путь к выходному файлу")
	command.Flags().StringVarP(&options.positions, "positions", "p", "0,0,0", "Начальные позиции роторов, например 0,0,0")
	return command
}

func execute(options encryptOptions) error {
	position, err := enigma.ParsePosition(options.positions)
	if err != nil {
		return fmt.Errorf("configure Enigma: %w", err)
	}
	machine := enigma.New(position)

	input, err := os.Open(options.input)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer input.Close()

	output, err := os.Create(options.output)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer output.Close()

	reader := bufio.NewReader(input)
	writer := bufio.NewWriter(output)
	buffer := make([]byte, 32*1024)
	for {
		count, readErr := reader.Read(buffer)
		if count > 0 {
			for index := range count {
				buffer[index] = machine.TransformByte(buffer[index])
			}
			if _, err := writer.Write(buffer[:count]); err != nil {
				return fmt.Errorf("write output file: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read input file: %w", readErr)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush output file: %w", err)
	}
	return nil
}
