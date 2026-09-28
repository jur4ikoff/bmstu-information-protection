// Package enigma implements a configurable 256-contact Enigma-style machine.
package enigma

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const alphabetSize = 256

var rotorDefinitions = map[string]struct {
	seed  uint32
	notch int
}{
	"I": {0xA341316C, 17}, "II": {0xC8013EA4, 91},
	"III": {0xAD90777D, 201}, "IV": {0x7E95761E, 143},
}

type rotor struct {
	wiring, reverse [alphabetSize]byte
	notch, position int
}

// Position contains initial positions from the far-left rotor to the right rotor.
type Position struct{ FarLeft, Left, Middle, Right byte }

// Config can be read from JSON. Plugboard entries are BYTE:BYTE pairs, either
// decimal (65:66) or hexadecimal (0x41:0x42).
type Config struct {
	Rotors    []string `json:"rotors"`
	Reflector string   `json:"reflector"`
	Positions string   `json:"positions"`
	Plugboard []string `json:"plugboard"`
}

func DefaultConfig() Config {
	return Config{Rotors: []string{"I", "II", "III", "IV"}, Reflector: "A", Positions: "0,0,0,0"}
}
func LoadConfig(path string) (Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	c := DefaultConfig()
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse config JSON: %w", err)
	}
	return c, nil
}

type Enigma struct {
	farLeft, left, middle, right rotor
	reflector, plugboard         [alphabetSize]byte
	key                          [32]byte
}

// New constructs the four-rotor machine with the default rotor order.
func New(position Position) *Enigma {
	c := DefaultConfig()
	c.Positions = fmt.Sprintf("%d,%d,%d,%d", position.FarLeft, position.Left, position.Middle, position.Right)
	m, err := NewConfigured(c)
	if err != nil {
		panic(err)
	}
	return m
}

// NewConfigured installs all four distinct rotors I..IV in a chosen order, a reflector and a
// combinatorial plugboard. The transform is symmetric with a fresh equal setup.
func NewConfigured(c Config) (*Enigma, error) {
	if len(c.Rotors) == 0 {
		c.Rotors = DefaultConfig().Rotors
	}
	if len(c.Rotors) != 4 {
		return nil, fmt.Errorf("exactly four rotors I, II, III and IV must be configured")
	}
	if c.Reflector == "" {
		c.Reflector = "A"
	}
	c.Reflector = strings.ToUpper(c.Reflector)
	if c.Positions == "" {
		c.Positions = "0,0,0,0"
	}
	p, err := ParsePosition(c.Positions)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	rotors := [4]rotor{}
	positions := [4]byte{p.FarLeft, p.Left, p.Middle, p.Right}
	for i, id := range c.Rotors {
		id = strings.ToUpper(strings.TrimSpace(id))
		d, ok := rotorDefinitions[id]
		if !ok || seen[id] {
			return nil, fmt.Errorf("invalid rotor selection %q", c.Rotors[i])
		}
		seen[id] = true
		c.Rotors[i] = id
		rotors[i] = newRotor(d.seed, d.notch, positions[i])
	}
	plugboard, err := parsePlugboard(c.Plugboard)
	if err != nil {
		return nil, err
	}
	reflector, err := newReflector(c.Reflector)
	if err != nil {
		return nil, err
	}
	m := &Enigma{farLeft: rotors[0], left: rotors[1], middle: rotors[2], right: rotors[3], reflector: reflector, plugboard: plugboard}
	canonical := struct {
		Rotors               []string
		Reflector, Positions string
		Plugboard            [alphabetSize]byte
	}{c.Rotors, c.Reflector, c.Positions, plugboard}
	b, _ := json.Marshal(canonical)
	m.key = sha256.Sum256(b)
	return m, nil
}

// AuthenticationKey is configuration-derived HMAC key material. It provides
// integrity/authentication, not modern confidentiality (Enigma is didactic).
func (m *Enigma) AuthenticationKey() []byte {
	result := make([]byte, len(m.key))
	copy(result, m.key[:])
	return result
}
func (m *Enigma) TransformByte(v byte) byte {
	m.stepRotors()
	encoded := m.plugboard[v]
	encoded = m.right.forward(encoded)
	encoded = m.middle.forward(encoded)
	encoded = m.left.forward(encoded)
	encoded = m.farLeft.forward(encoded)
	encoded = m.reflector[encoded]
	encoded = m.farLeft.backward(encoded)
	encoded = m.left.backward(encoded)
	encoded = m.middle.backward(encoded)
	encoded = m.right.backward(encoded)
	return m.plugboard[encoded]
}
func (m *Enigma) Transform(buffer []byte) {
	for i := range buffer {
		buffer[i] = m.TransformByte(buffer[i])
	}
}
func (m *Enigma) Advance(n int64) {
	for ; n > 0; n-- {
		m.stepRotors()
	}
}
func (m *Enigma) stepRotors() {
	leftAtNotch := m.left.position == m.left.notch
	middleAtNotch := m.middle.position == m.middle.notch
	rightAtNotch := m.right.position == m.right.notch
	if leftAtNotch {
		m.farLeft.step()
	}
	if leftAtNotch || middleAtNotch {
		m.left.step()
	}
	if middleAtNotch || rightAtNotch {
		m.middle.step()
	}
	m.right.step()
}

func ParsePosition(value string) (Position, error) {
	parts := strings.Split(value, ",")
	if len(parts) != 4 {
		return Position{}, fmt.Errorf("positions must contain four comma-separated values from 0 to 255")
	}
	values := [4]byte{}
	for i, part := range parts {
		parsed, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || parsed < 0 || parsed >= alphabetSize {
			return Position{}, fmt.Errorf("invalid rotor position %q: expected a value from 0 to 255", part)
		}
		values[i] = byte(parsed)
	}
	return Position{values[0], values[1], values[2], values[3]}, nil
}

func parsePlugboard(pairs []string) ([alphabetSize]byte, error) {
	result := identity()
	used := [alphabetSize]bool{}
	for _, pair := range pairs {
		parts := strings.Split(pair, ":")
		if len(parts) != 2 {
			return result, fmt.Errorf("invalid plugboard pair %q: use BYTE:BYTE", pair)
		}
		a, errA := parseByte(parts[0])
		b, errB := parseByte(parts[1])
		if errA != nil || errB != nil || a == b || used[a] || used[b] {
			return result, fmt.Errorf("invalid or overlapping plugboard pair %q", pair)
		}
		used[a], used[b] = true, true
		result[a], result[b] = b, a
	}
	return result, nil
}
func parseByte(s string) (byte, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 8)
	return byte(n), err
}
func identity() [alphabetSize]byte {
	var r [alphabetSize]byte
	for i := range r {
		r[i] = byte(i)
	}
	return r
}
func newRotor(seed uint32, notch int, position byte) rotor {
	wiring := permutation(seed)
	r := rotor{wiring: wiring, notch: notch, position: int(position)}
	for i, target := range wiring {
		r.reverse[target] = byte(i)
	}
	return r
}
func permutation(seed uint32) [alphabetSize]byte {
	r := identity()
	for i := alphabetSize - 1; i > 0; i-- {
		seed = seed*1664525 + 1013904223
		j := int(seed % uint32(i+1))
		r[i], r[j] = r[j], r[i]
	}
	return r
}
func newReflector(name string) ([alphabetSize]byte, error) {
	r := identity()
	switch name {
	case "A":
		for i := range r {
			r[i] = byte(i ^ 0x80)
		}
	case "B":
		p := permutation(0xD1B54A32)
		for i := 0; i < alphabetSize; i += 2 {
			r[p[i]], r[p[i+1]] = p[i+1], p[i]
		}
	default:
		return r, fmt.Errorf("unknown reflector %q: use A or B", name)
	}
	return r, nil
}
func (r *rotor) step() { r.position = (r.position + 1) % alphabetSize }
func (r rotor) forward(v byte) byte {
	shifted := (int(v) + r.position) % alphabetSize
	return byte((int(r.wiring[shifted]) - r.position + alphabetSize) % alphabetSize)
}
func (r rotor) backward(v byte) byte {
	shifted := (int(v) + r.position) % alphabetSize
	return byte((int(r.reverse[shifted]) - r.position + alphabetSize) % alphabetSize)
}
