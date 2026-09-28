package archive

import (
	"archive/tar"
	"archive/zip"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"github.com/ypopov2005/bmstu-information-protection/internal/enigma"
)

const manifestName = ".enigma-auth.json"

type manifest struct {
	Version int      `json:"version"`
	Files   []string `json:"files"`
	HMAC    string   `json:"hmac"`
}

// TransformEntries changes only requested files in a ZIP/TAR while streaming
// entry contents. It stores an authenticated manifest inside the archive.
func TransformEntries(input, output string, machine *enigma.Enigma, decrypt bool, names []string) error {
	t, err := typeOf(input)
	if err != nil {
		return err
	}
	if t == 1 {
		return transformZIP(input, output, machine, decrypt, names)
	}
	return transformTAR(input, output, machine, decrypt, names)
}
func nameSet(names []string) map[string]bool {
	r := map[string]bool{}
	for _, n := range names {
		if n != "" {
			r[n] = true
		}
	}
	return r
}
func macFor(machine *enigma.Enigma) hash.Hash {
	return hmac.New(sha256.New, machine.AuthenticationKey())
}

func transformZIP(input, output string, machine *enigma.Enigma, decrypt bool, names []string) error {
	f, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("open ZIP: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	reader, err := zip.NewReader(f, info.Size())
	if err != nil {
		return fmt.Errorf("read ZIP directory: %w", err)
	}
	selected := nameSet(names)
	if decrypt {
		m, err := readZIPManifest(reader)
		if err != nil {
			return err
		}
		if err := verifyZIP(reader, machine, m); err != nil {
			return err
		}
		selected = nameSet(m.Files)
	} else if _, err := readZIPManifest(reader); err == nil {
		return fmt.Errorf("ZIP already contains reserved %s entry", manifestName)
	}
	return atomicOutput(output, func(out *os.File) error {
		writer := zip.NewWriter(out)
		mac := macFor(machine)
		for _, file := range reader.File {
			if file.Name == manifestName {
				continue
			}
			header := file.FileHeader
			entry, err := writer.CreateHeader(&header)
			if err != nil {
				return err
			}
			source, err := file.Open()
			if err != nil {
				return err
			}
			if err := copyEntry(source, entry, mac, file.Name, selected[file.Name], machine); err != nil {
				source.Close()
				return err
			}
			if err := source.Close(); err != nil {
				return err
			}
		}
		if !decrypt {
			data, err := json.Marshal(manifest{Version: 1, Files: names, HMAC: hex.EncodeToString(mac.Sum(nil))})
			if err != nil {
				return err
			}
			entry, err := writer.Create(manifestName)
			if err != nil {
				return err
			}
			if _, err := entry.Write(data); err != nil {
				return err
			}
		}
		return writer.Close()
	})
}

func readZIPManifest(reader *zip.Reader) (manifest, error) {
	for _, f := range reader.File {
		if f.Name == manifestName {
			r, err := f.Open()
			if err != nil {
				return manifest{}, err
			}
			defer r.Close()
			var m manifest
			if err := json.NewDecoder(r).Decode(&m); err != nil {
				return m, fmt.Errorf("parse archive manifest: %w", err)
			}
			if m.Version != 1 {
				return m, fmt.Errorf("unsupported archive manifest")
			}
			return m, nil
		}
	}
	return manifest{}, fmt.Errorf("archive manifest %s not found", manifestName)
}
func verifyZIP(reader *zip.Reader, machine *enigma.Enigma, m manifest) error {
	expected, err := hex.DecodeString(m.HMAC)
	if err != nil {
		return fmt.Errorf("invalid archive manifest HMAC")
	}
	mac := macFor(machine)
	for _, f := range reader.File {
		if f.Name == manifestName {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		if err := copyEntry(r, io.Discard, mac, f.Name, false, nil); err != nil {
			r.Close()
			return err
		}
		r.Close()
	}
	if subtle.ConstantTimeCompare(expected, mac.Sum(nil)) != 1 {
		return fmt.Errorf("authentication failed: wrong configuration or modified archive")
	}
	return nil
}

func transformTAR(input, output string, machine *enigma.Enigma, decrypt bool, names []string) error {
	selected := nameSet(names)
	if decrypt {
		m, err := readTARManifest(input)
		if err != nil {
			return err
		}
		if err := verifyTAR(input, machine, m); err != nil {
			return err
		}
		selected = nameSet(m.Files)
	} else if _, err := readTARManifest(input); err == nil {
		return fmt.Errorf("TAR already contains reserved %s entry", manifestName)
	}
	f, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("open TAR: %w", err)
	}
	defer f.Close()
	reader := tar.NewReader(f)
	return atomicOutput(output, func(out *os.File) error {
		writer := tar.NewWriter(out)
		mac := macFor(machine)
		for {
			header, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("read TAR: %w", err)
			}
			if header.Name == manifestName {
				continue
			}
			copied := *header
			if err := writer.WriteHeader(&copied); err != nil {
				return err
			}
			if err := copyEntry(reader, writer, mac, header.Name, selected[header.Name], machine); err != nil {
				return err
			}
		}
		if !decrypt {
			data, err := json.Marshal(manifest{Version: 1, Files: names, HMAC: hex.EncodeToString(mac.Sum(nil))})
			if err != nil {
				return err
			}
			if err := writer.WriteHeader(&tar.Header{Name: manifestName, Mode: 0600, Size: int64(len(data)), ModTime: time.Unix(0, 0)}); err != nil {
				return err
			}
			if _, err := writer.Write(data); err != nil {
				return err
			}
		}
		return writer.Close()
	})
}

func readTARManifest(path string) (manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return manifest{}, err
	}
	defer f.Close()
	r := tar.NewReader(f)
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return manifest{}, err
		}
		if h.Name == manifestName {
			var m manifest
			if err := json.NewDecoder(r).Decode(&m); err != nil {
				return m, fmt.Errorf("parse archive manifest: %w", err)
			}
			if m.Version != 1 {
				return m, fmt.Errorf("unsupported archive manifest")
			}
			return m, nil
		}
	}
	return manifest{}, fmt.Errorf("archive manifest %s not found", manifestName)
}
func verifyTAR(path string, machine *enigma.Enigma, m manifest) error {
	expected, err := hex.DecodeString(m.HMAC)
	if err != nil {
		return fmt.Errorf("invalid archive manifest HMAC")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, mac := tar.NewReader(f), macFor(machine)
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Name == manifestName {
			continue
		}
		if err := copyEntry(r, io.Discard, mac, h.Name, false, nil); err != nil {
			return err
		}
	}
	if subtle.ConstantTimeCompare(expected, mac.Sum(nil)) != 1 {
		return fmt.Errorf("authentication failed: wrong configuration or modified archive")
	}
	return nil
}

// copyEntry emits a stable logical MAC: name delimiter followed by entry data.
// During encryption the transformed (ciphertext) bytes are authenticated.
func copyEntry(source io.Reader, target io.Writer, mac hash.Hash, name string, transform bool, machine *enigma.Enigma) error {
	_, _ = mac.Write(append(append([]byte(nil), []byte(name)...), 0))
	buffer := make([]byte, 64*1024)
	for {
		n, err := source.Read(buffer)
		if n > 0 {
			data := buffer[:n]
			if transform {
				machine.Transform(data)
			}
			_, _ = mac.Write(data)
			if _, writeErr := target.Write(data); writeErr != nil {
				return writeErr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
