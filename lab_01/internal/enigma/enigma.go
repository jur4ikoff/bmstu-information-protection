// Package enigma implements a 256-contact Enigma-style machine.
package enigma

import (
	"fmt"
	"strconv"
	"strings"
)

const alphabetSize = 256

type rotor struct {
	wiring   [alphabetSize]byte
	reverse  [alphabetSize]byte
	notch    int
	position int
}

// Position contains the initial positions of the left, middle, and right
// rotors. Every byte value from 0 to 255 is valid.
type Position struct {
	Left   byte
	Middle byte
	Right  byte
}

type Enigma struct {
	left      rotor
	middle    rotor
	right     rotor
	reflector [alphabetSize]byte
}

// New constructs a machine with three fixed 256-contact rotors.
func New(position Position) *Enigma {
	return &Enigma{
		left:      newRotor(0xA341316C, 17, position.Left),
		middle:    newRotor(0xC8013EA4, 91, position.Middle),
		right:     newRotor(0xAD90777D, 201, position.Right),
		reflector: newReflector(),
	}
}

// TransformByte encrypts one byte. It advances the rotors before every byte
// and is reversible when used with a fresh machine with the same settings.
func (machine *Enigma) TransformByte(value byte) byte {
	machine.stepRotors()
	encoded := machine.right.forward(value)
	encoded = machine.middle.forward(encoded)
	encoded = machine.left.forward(encoded)
	encoded = machine.reflector[encoded]
	encoded = machine.left.backward(encoded)
	encoded = machine.middle.backward(encoded)
	return machine.right.backward(encoded)
}

func (machine *Enigma) stepRotors() {
	// This preserves Enigma's characteristic double-step behaviour.
	middleAtNotch := machine.middle.position == machine.middle.notch
	rightAtNotch := machine.right.position == machine.right.notch
	if middleAtNotch {
		machine.left.step()
	}
	if middleAtNotch || rightAtNotch {
		machine.middle.step()
	}
	machine.right.step()
}

func ParsePosition(value string) (Position, error) {
	parts := strings.Split(value, ",")
	if len(parts) != 3 {
		return Position{}, fmt.Errorf("positions must contain three comma-separated values from 0 to 255")
	}

	values := [3]byte{}
	for index, part := range parts {
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 0 || parsed >= alphabetSize {
			return Position{}, fmt.Errorf("invalid rotor position %q: expected a value from 0 to 255", part)
		}
		values[index] = byte(parsed)
	}
	return Position{Left: values[0], Middle: values[1], Right: values[2]}, nil
}

func newRotor(seed uint32, notch int, position byte) rotor {
	wiring := permutation(seed)
	result := rotor{
		wiring:   wiring,
		notch:    notch,
		position: int(position),
	}
	for index, target := range wiring {
		result.reverse[target] = byte(index)
	}
	return result
}

func permutation(seed uint32) [alphabetSize]byte {
	var result [alphabetSize]byte
	for index := range result {
		result[index] = byte(index)
	}
	for index := alphabetSize - 1; index > 0; index-- {
		seed = seed*1664525 + 1013904223
		target := int(seed % uint32(index+1))
		result[index], result[target] = result[target], result[index]
	}
	return result
}

func newReflector() [alphabetSize]byte {
	var result [alphabetSize]byte
	for index := range result {
		result[index] = byte(index ^ 0x80)
	}
	return result
}

func (rotorValue *rotor) step() {
	rotorValue.position = (rotorValue.position + 1) % alphabetSize
}

func (rotorValue rotor) forward(value byte) byte {
	shifted := (int(value) + rotorValue.position) % alphabetSize
	return byte((int(rotorValue.wiring[shifted]) - rotorValue.position + alphabetSize) % alphabetSize)
}

func (rotorValue rotor) backward(value byte) byte {
	shifted := (int(value) + rotorValue.position) % alphabetSize
	return byte((int(rotorValue.reverse[shifted]) - rotorValue.position + alphabetSize) % alphabetSize)
}
