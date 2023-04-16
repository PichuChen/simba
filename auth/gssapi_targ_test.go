package auth

import (
	encoding_asn1 "encoding/asn1"
	"encoding/hex"
	"testing"
)

func TestGSSAPINegTokenTargDecode(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		expected TargPayload
	}{
		{
			name: "response from samba, NTLMSSP_NEGOTIATE",
			input: func() []byte {
				r, _ := hex.DecodeString("a181c43081c1a0030a0101a10c060a2b06010401823702020aa281ab0481a84e544c4d5353500002000000140014003800000015828ae2b5bdb4abf704918f00000000000000005c005c004c000000060100000000000f4d00420056004d00320032003100320030003800020014004d00420056004d00320032003100320030003800010014004d00420056004d0032003200310032003000380004000000030014006d00620076006d003200320031003200300038000700080060bbda0f486dd90100000000")
				return r
			}(),
			expected: TargPayload{
				NegResult:     0x01,
				SupportedMech: MechType(encoding_asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10})),
				ResponseToken: func() []byte {
					r, _ := hex.DecodeString("4e544c4d5353500002000000140014003800000015828ae2b5bdb4abf704918f00000000000000005c005c004c000000060100000000000f4d00420056004d00320032003100320030003800020014004d00420056004d00320032003100320030003800010014004d00420056004d0032003200310032003000380004000000030014006d00620076006d003200320031003200300038000700080060bbda0f486dd90100000000")
					return r
				}(),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, err := NewTargPayload(c.input)
			if err != nil {
				t.Errorf("NewTargPayload() = %v, want %v", err, nil)
				return
			}

			if actual.NegResult != c.expected.NegResult {
				t.Errorf("NewTargPayload().NegResult = %v, want %v", actual.NegResult, c.expected.NegResult)
			}

			if encoding_asn1.ObjectIdentifier(actual.SupportedMech).String() != encoding_asn1.ObjectIdentifier(c.expected.SupportedMech).String() {
				t.Errorf("NewTargPayload().SupportedMech = %v, want %v", actual.SupportedMech, c.expected.SupportedMech)
			}

			if hex.EncodeToString(actual.ResponseToken) != hex.EncodeToString(c.expected.ResponseToken) {
				t.Errorf("NewTargPayload().ResponseToken = %v, want %v", actual.ResponseToken, c.expected.ResponseToken)
			}

			if hex.EncodeToString(actual.MechListMIC) != hex.EncodeToString(c.expected.MechListMIC) {
				t.Errorf("NewTargPayload().MechListMIC = %v, want %v", actual.MechListMIC, c.expected.MechListMIC)
			}
		})
	}
}

func TestGSSAPINegTokenTargEncode(t *testing.T) {
	cases := []struct {
		name     string
		input    TargPayload
		expected []byte
	}{
		{
			name: "basic",
			input: TargPayload{
				NegResult:     0x01,
				SupportedMech: MechType(encoding_asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10})),
				ResponseToken: func() []byte {
					r, _ := hex.DecodeString("4e544c4d5353500002000000140014003800000015828ae2b5bdb4abf704918f00000000000000005c005c004c000000060100000000000f4d00420056004d00320032003100320030003800020014004d00420056004d00320032003100320030003800010014004d00420056004d0032003200310032003000380004000000030014006d00620076006d003200320031003200300038000700080060bbda0f486dd90100000000")
					return r
				}(),
			},
			expected: func() []byte {
				r, _ := hex.DecodeString("a181c43081c1a0030a0101a10c060a2b06010401823702020aa281ab0481a84e544c4d5353500002000000140014003800000015828ae2b5bdb4abf704918f00000000000000005c005c004c000000060100000000000f4d00420056004d00320032003100320030003800020014004d00420056004d00320032003100320030003800010014004d00420056004d0032003200310032003000380004000000030014006d00620076006d003200320031003200300038000700080060bbda0f486dd90100000000")
				return r
			}(),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, err := c.input.Bytes()
			if err != nil {
				t.Errorf("Encode() = %v, want %v", err, nil)
				return
			}
			if hex.EncodeToString(actual) != hex.EncodeToString(c.expected) {
				if len(actual) != len(c.expected) {
					t.Logf("actual length = %d, want %d", len(actual), len(c.expected))
					for i := range actual {
						if actual[i] != c.expected[i] {
							t.Logf("actual[%d] = %0x, want %0x", i, actual[i], c.expected[i])
							break
						}
					}
				} else {
					for i := range actual {
						if actual[i] != c.expected[i] {
							t.Logf("actual[%d] = %0x, want %0x", i, actual[i], c.expected[i])
						}
					}
				}
				t.Errorf("Encode() = %0x, want %0x", actual, c.expected)
			}
		})
	}

}
