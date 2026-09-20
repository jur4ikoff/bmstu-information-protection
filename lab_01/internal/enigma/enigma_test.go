package enigma

import "testing"

func TestTransformDecryptsWithSameSettings(t *testing.T) {
	plainText := make([]byte, 512)
	for index := range plainText {
		plainText[index] = byte(index)
	}
	position := Position{Left: 12, Middle: 34, Right: 56}
	encryptor := New(position)
	decryptor := New(position)

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
	if _, err := ParsePosition("0,0,256"); err == nil {
		t.Fatal("ParsePosition accepted an out-of-range rotor position")
	}
}

func TestNewKeepsBytePosition(t *testing.T) {
	machine := New(Position{Left: 255})
	if got, want := machine.left.position, 255; got != want {
		t.Fatalf("left rotor position = %d, want %d", got, want)
	}
}
