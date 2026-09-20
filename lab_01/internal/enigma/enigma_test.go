package enigma

import "testing"

func TestTransformDecryptsWithSameSettings(t *testing.T) {
	plainText := make([]byte, 512)
	for index := range plainText {
		plainText[index] = byte(index)
	}
	encryptor, err := New("12,34,56")
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := New("12,34,56")
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

func TestNewRejectsInvalidPositions(t *testing.T) {
	if _, err := New("0,0,256"); err == nil {
		t.Fatal("New accepted an out-of-range rotor position")
	}
}

func TestNewKeepsBytePosition(t *testing.T) {
	machine, err := New("255,0,0")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := machine.left.position, 255; got != want {
		t.Fatalf("left rotor position = %d, want %d", got, want)
	}
}
