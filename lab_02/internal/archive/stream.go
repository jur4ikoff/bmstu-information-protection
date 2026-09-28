// Package archive implements authenticated, streaming Enigma archive envelopes.
package archive

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ypopov2005/bmstu-information-protection/internal/enigma"
)

const (
	headerSize = 36
	tagSize    = sha256.Size
)

var magic = [8]byte{'E', 'N', 'I', 'G', 'A', 'R', '1', 0}

// Encrypt wraps a ZIP or TAR in an authenticated binary envelope. The source
// is read once in 64 KiB chunks and is never held fully in memory.
func Encrypt(inputPath, outputPath string, machine *enigma.Enigma) error {
	input, info, err := openInput(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()
	archiveType, err := typeOf(inputPath)
	if err != nil {
		return err
	}
	header := makeHeader(info.Size(), archiveType, machine.AuthenticationKey())
	return atomicOutput(outputPath, func(output *os.File) error {
		mac := hmac.New(sha256.New, machine.AuthenticationKey())
		if _, err := output.Write(header); err != nil {
			return err
		}
		_, _ = mac.Write(header)
		buffer := make([]byte, 64*1024)
		for {
			n, readErr := input.Read(buffer)
			if n > 0 {
				machine.Transform(buffer[:n])
				if _, err := output.Write(buffer[:n]); err != nil {
					return fmt.Errorf("write encrypted archive: %w", err)
				}
				_, _ = mac.Write(buffer[:n])
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return fmt.Errorf("read archive: %w", readErr)
			}
		}
		_, err := output.Write(mac.Sum(nil))
		return err
	})
}

// Decrypt verifies the HMAC before publishing output. A wrong rotor setup or
// damaged input therefore cannot replace or corrupt an existing archive file.
func Decrypt(inputPath, outputPath string, machine *enigma.Enigma) error {
	input, info, err := openInput(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()
	if info.Size() < headerSize+tagSize {
		return fmt.Errorf("encrypted archive is too short")
	}
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(input, header); err != nil {
		return fmt.Errorf("read envelope header: %w", err)
	}
	plainSize, archiveType, err := checkHeader(header, machine.AuthenticationKey())
	if err != nil {
		return err
	}
	cipherSize := info.Size() - headerSize - tagSize
	if plainSize != uint64(cipherSize) {
		return fmt.Errorf("invalid envelope length")
	}
	if archiveType != 1 && archiveType != 2 {
		return fmt.Errorf("unsupported archive type in envelope")
	}
	mac := hmac.New(sha256.New, machine.AuthenticationKey())
	_, _ = mac.Write(header)
	return atomicOutput(outputPath, func(output *os.File) error {
		limited := io.LimitReader(input, cipherSize)
		buffer := make([]byte, 64*1024)
		for {
			n, readErr := limited.Read(buffer)
			if n > 0 {
				_, _ = mac.Write(buffer[:n])
				machine.Transform(buffer[:n])
				if _, err := output.Write(buffer[:n]); err != nil {
					return fmt.Errorf("write decrypted archive: %w", err)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return fmt.Errorf("read encrypted archive: %w", readErr)
			}
		}
		tag := make([]byte, tagSize)
		if _, err := io.ReadFull(input, tag); err != nil {
			return fmt.Errorf("read authentication tag: %w", err)
		}
		if subtle.ConstantTimeCompare(tag, mac.Sum(nil)) != 1 {
			return fmt.Errorf("authentication failed: wrong Enigma configuration or corrupted ciphertext")
		}
		return nil
	})
}

func typeOf(path string) (byte, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".zip":
		return 1, nil
	case ".tar":
		return 2, nil
	default:
		return 0, fmt.Errorf("only .zip and .tar archives are supported")
	}
}
func makeHeader(size int64, archiveType byte, key []byte) []byte {
	h := make([]byte, headerSize)
	copy(h, magic[:])
	h[8] = 1
	h[9] = archiveType
	binary.BigEndian.PutUint64(h[12:20], uint64(size))
	fingerprint := sha256.Sum256(key)
	copy(h[20:], fingerprint[:16])
	return h
}
func checkHeader(h, key []byte) (uint64, byte, error) {
	if string(h[:8]) != string(magic[:]) || h[8] != 1 {
		return 0, 0, fmt.Errorf("not an ENIGAR1 archive")
	}
	fingerprint := sha256.Sum256(key)
	if subtle.ConstantTimeCompare(h[20:], fingerprint[:16]) != 1 {
		return 0, 0, fmt.Errorf("configuration fingerprint differs: refusing to decrypt")
	}
	return binary.BigEndian.Uint64(h[12:20]), h[9], nil
}
func openInput(path string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open input: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("stat input: %w", err)
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("input is not a regular file")
	}
	return f, info, nil
}
func atomicOutput(path string, write func(*os.File) error) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".enigma-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tempName := temp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tempName)
		}
	}()
	if err := write(temp); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	ok = true
	return nil
}
