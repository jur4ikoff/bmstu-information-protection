package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/ypopov2005/bmstu-information-protection/pkg/enigma"
)

type encryptOptions struct {
	input     string
	output    string
	positions string
	plugboard string
}

func newEncryptCommand() *cobra.Command {
	options := encryptOptions{}
	command := &cobra.Command{
		Use:   "encrypt",
		Short: "Зашифровать входной файл",
		RunE: func(_ *cobra.Command, _ []string) error {
			return encryptFile(options)
		},
	}

	command.Flags().StringVarP(&options.input, "input", "i", "", "Путь к входному файлу")
	command.Flags().StringVarP(&options.output, "output", "o", "", "Путь к зашифрованному файлу")
	command.Flags().StringVarP(&options.positions, "positions", "p", "AAA", "Начальные позиции роторов, например MCK")
	command.Flags().StringVar(&options.plugboard, "plugboard", "", "Пары штекерной панели через пробел, например \"AV BS CG\"")
	_ = command.MarkFlagRequired("input")
	_ = command.MarkFlagRequired("output")
	return command
}

func encryptFile(options encryptOptions) error {
	machine, err := enigma.New(options.positions, options.plugboard)
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
			for index := 0; index < count; index++ {
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
