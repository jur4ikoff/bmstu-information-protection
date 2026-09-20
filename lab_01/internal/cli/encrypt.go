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
	return newTransformCommand("encrypt", "Зашифровать входной файл")
}

func newDecryptCommand() *cobra.Command {
	return newTransformCommand("decrypt", "Расшифровать входной файл")
}

func newTransformCommand(use, short string) *cobra.Command {
	options := encryptOptions{}
	command := &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(_ *cobra.Command, _ []string) error {
			return execute(options)
		},
	}

	command.Flags().StringVarP(&options.input, "input", "i", "", "Путь к входному файлу")
	command.Flags().StringVarP(&options.output, "output", "o", "output.txt", "Путь к выходному файлу")
	command.Flags().StringVarP(&options.positions, "positions", "p", "0,0,0", "Начальные позиции роторов, например 0,0,0")
	_ = command.MarkFlagRequired("input")
	return command
}

func execute(options encryptOptions) error {
	machine, err := enigma.New(options.positions)

	if err != nil {
		return fmt.Errorf("настройка Enigma: %w", err)
	}

	input, err := os.Open(options.input)
	if err != nil {
		return fmt.Errorf("открытие входного файла: %w", err)
	}
	defer input.Close()

	output, err := os.Create(options.output)
	if err != nil {
		return fmt.Errorf("создание выходного файла: %w", err)
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
				return fmt.Errorf("запись выходного файла: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("чтение входного файла: %w", readErr)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("сохранение выходного файла: %w", err)
	}
	return nil
}
