package ntlmssp

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Azure/go-ntlmssp"
)

func MustDecodeHex(s string) []byte {
	v, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return v
}

func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for k, v := range a {
		if v != b[k] {
			return false
		}
	}

	return true
}

// Print out hex dump of byte slice
// example:
// 000000: 4e 54 4c 4d 53 53 50 00 02 00 00 00 00 00 00 00  NTLMSSP.........
// 000010: 00 00 00 00 00 00 00 00                          ........
func dumpHex(b []byte) string {
	lineN := len(b) / 16
	out := ""
	for i := 0; i < lineN; i++ {
		line := b[i*16 : i*16+16]
		// print address
		out += fmt.Sprintf("%06X:", i*16)
		// print hex
		for _, v := range line {
			out += fmt.Sprintf(" %02x", v)
		}
		// print ascii
		out += fmt.Sprintf(" ")
		for _, v := range line {
			if v >= 0x20 && v <= 0x7e {
				out += fmt.Sprintf("%c", v)
			} else {
				out += fmt.Sprintf(".")
			}
		}
		out += fmt.Sprintf("\n")
	}

	// last line
	if len(b)%16 == 0 {
		return out
	}
	line := b[lineN*16:]
	// print address
	out += fmt.Sprintf("%06X:", lineN*16)
	// print hex
	for _, v := range line {
		out += fmt.Sprintf(" %02x", v)
	}
	// print padding
	for i := 0; i < 16-len(line); i++ {
		out += fmt.Sprintf("   ")
	}
	// print ascii
	out += fmt.Sprintf(" ")
	for _, v := range line {
		if v >= 0x20 && v <= 0x7e {
			out += fmt.Sprintf("%c", v)
		} else {
			out += fmt.Sprintf(".")
		}
	}

	out += fmt.Sprintf("\n")
	return out
}

func TestNewNegotianteMessage(t *testing.T) {
	cases := []struct {
		domainName  string
		workstation string
		expected    []byte
	}{
		{
			"Domain",
			"WORKGROUP",
			MustDecodeHex("" +
				"4e544c4d53535000" + // Signature
				"01000000013088a0" + // MessageType, NegotiateFlags
				"0600060028000000" + // DomainNameFields
				"090009002e000000" + // WorkstationFields
				"0601b11d0000000f" + // Version
				"444f4d41494e" + // DOMAIN
				"574f524b47524f5550"), // Workstation
		},
	}

	for _, c := range cases {
		actual, err := ntlmssp.NewNegotiateMessage(c.domainName, c.workstation)
		if err != nil {
			t.Errorf("NewNegotiateMessage(%s, %s) == %v, expected %v", c.domainName, c.workstation, err, c.expected)
		}

		if !compareBytes(actual, c.expected) {
			t.Errorf("NewNegotiateMessage(%s, %s) == actual:\n%v, expected:\n%v", c.domainName, c.workstation, dumpHex(actual), dumpHex(c.expected))
		}
	}

}
