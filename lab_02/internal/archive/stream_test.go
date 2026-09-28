package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ypopov2005/bmstu-information-protection/internal/enigma"
)

func testMachine(t *testing.T, positions string) *enigma.Enigma {
	t.Helper()
	m, err := enigma.NewConfigured(enigma.Config{Rotors: []string{"IV", "II", "I", "III"}, Reflector: "B", Positions: positions, Plugboard: []string{"65:66", "1:255"}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func makeZIP(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, value := range map[string]string{"dir/data.txt": "large-enough test payload", "empty": ""} {
		e, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEnvelopeRoundTripAndWrongConfigDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.zip")
	want := makeZIP(t, input)
	encrypted, decoded := filepath.Join(dir, "cipher.egar"), filepath.Join(dir, "decoded.zip")
	if err := Encrypt(input, encrypted, testMachine(t, "7,12,34,56")); err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(encrypted, decoded, testMachine(t, "7,12,34,56")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("archive bytes changed after envelope round trip")
	}
	protected := filepath.Join(dir, "protected.zip")
	if err := os.WriteFile(protected, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(encrypted, protected, testMachine(t, "7,12,34,57")); err == nil {
		t.Fatal("wrong configuration was accepted")
	}
	got, err = os.ReadFile(protected)
	if err != nil || string(got) != "keep" {
		t.Fatal("failed decryption published output")
	}
}

func TestZIPSelectedEntriesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.zip")
	makeZIP(t, input)
	partial, decoded := filepath.Join(dir, "partial.zip"), filepath.Join(dir, "decoded.zip")
	if err := TransformEntries(input, partial, testMachine(t, "0,1,2,3"), false, []string{"dir/data.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := TransformEntries(partial, decoded, testMachine(t, "0,1,2,3"), true, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{input, decoded} {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := f.Stat()
		reader, err := zip.NewReader(f, info.Size())
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range reader.File {
			if entry.Name == "dir/data.txt" {
				r, _ := entry.Open()
				value := new(bytes.Buffer)
				value.ReadFrom(r)
				if value.String() != "large-enough test payload" {
					t.Fatalf("bad selected entry in %s", path)
				}
				r.Close()
			}
		}
		f.Close()
	}
}

func TestTARSelectedEntriesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.tar")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w := tar.NewWriter(f)
	for _, entry := range []struct{ name, data string }{{"nested/data", "tar payload"}, {"empty", ""}} {
		if err := w.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	partial, decoded := filepath.Join(dir, "partial.tar"), filepath.Join(dir, "decoded.tar")
	if err := TransformEntries(input, partial, testMachine(t, "0,3,2,1"), false, []string{"nested/data"}); err != nil {
		t.Fatal(err)
	}
	if err := TransformEntries(partial, decoded, testMachine(t, "0,3,2,1"), true, nil); err != nil {
		t.Fatal(err)
	}
	f, err = os.Open(decoded)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := tar.NewReader(f)
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "nested/data" {
			got, _ := io.ReadAll(r)
			if string(got) != "tar payload" {
				t.Fatalf("got %q", got)
			}
		}
	}
}
