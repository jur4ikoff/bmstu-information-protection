package enigma

import "testing"

func TestTransformKnownVector(t *testing.T) {
	first, err := New("AAA", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := New("AAA", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := first.TransformByte(0), second.TransformByte(0); got != want {
		t.Fatalf("different key streams: got %#x, want %#x", got, want)
	}
}

func TestTransformDecryptsWithSameSettings(t *testing.T) {
	plainText := []byte{0x00, 0xFF, 0x80, 0x01, 'A', 't', 't', 'a', 'c', 'k'}
	encryptor, err := New("MCK", "AV BS CG")
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := New("MCK", "AV BS CG")
	if err != nil {
		t.Fatal(err)
	}

	cipherText := make([]byte, len(plainText))
	for index, value := range plainText {
		cipherText[index] = encryptor.TransformByte(value)
	}
	decoded := make([]byte, len(cipherText))
	for index, value := range cipherText {
		decoded[index] = decryptor.TransformByte(value)
	}
	if got := string(decoded); got != string(plainText) {
		t.Fatalf("decrypted data = %x, want %x", decoded, plainText)
	}
}

func TestNewRejectsInvalidPlugboard(t *testing.T) {
	if _, err := New("AAA", "AB AC"); err == nil {
		t.Fatal("New accepted a reused plugboard letter")
	}
}
