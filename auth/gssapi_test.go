package auth

import (
	encoding_asn1 "encoding/asn1"
	"encoding/hex"
	"testing"
)

func TestGSSAPIDecode(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		expected InitPayload
	}{
		{
			name: "test",
			input: func() []byte {
				r, _ := hex.DecodeString("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000158288e2000000000000000000000000000000000a0000000000000f")
				return r
			}(),
			expected: InitPayload{
				OID: encoding_asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 2}),
				Token: NegotiationToken{
					NegTokenInit: NegTokenInitData{
						MechTypes: MechTypeList{
							MechType(encoding_asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10})),
						},
						ReqFlags: encoding_asn1.BitString{Bytes: []byte{}, BitLength: 0},
						MechToken: []byte{
							0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x88, 0xe2, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 0x0a, 00, 00, 00, 00, 00, 00, 0x0f,
						},
					},
				},
			},
		},
		{
			name: "response from samba",
			input: func() []byte {
				r, _ := hex.DecodeString("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265")
				return r
			}(),
			expected: InitPayload{
				OID: encoding_asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 2}),
				Token: NegotiationToken{
					NegTokenInit: NegTokenInitData{
						MechTypes: MechTypeList{
							MechType(encoding_asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10})),
						},
						ReqFlags:  encoding_asn1.BitString{Bytes: []byte{}, BitLength: 0},
						NegHints:  []byte("not_defined_in_RFC4178@please_ignore"),
						MechToken: []byte{},
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// var actual InitPayload
			actual, err := NewInitPayload(c.input)
			if err != nil {
				t.Errorf("NewInitPayload() = %v, want %v", err, nil)
				return
			}
			if actual.OID.String() != c.expected.OID.String() {
				t.Errorf("NewInitPayload().OID = %v, want %v", actual.OID, c.expected.OID)
			}

			if actual.Token.NegTokenInit.ReqFlags.BitLength != c.expected.Token.NegTokenInit.ReqFlags.BitLength ||
				hex.EncodeToString(actual.Token.NegTokenInit.ReqFlags.Bytes) != hex.EncodeToString(c.expected.Token.NegTokenInit.ReqFlags.Bytes) {
				t.Errorf("NewInitPayload().Token.NegTokenInit.ReqFlags = %v, want %v", actual.Token.NegTokenInit.ReqFlags, c.expected.Token.NegTokenInit.ReqFlags)
			}

			if hex.EncodeToString(actual.Token.NegTokenInit.MechToken) != hex.EncodeToString(c.expected.Token.NegTokenInit.MechToken) {
				t.Errorf("NewInitPayload().Token.NegTokenInit.MechToken = %v, want %v", actual.Token.NegTokenInit.MechToken, c.expected.Token.NegTokenInit.MechToken)
			}

			if len(actual.Token.NegTokenInit.MechTypes) != len(c.expected.Token.NegTokenInit.MechTypes) {
				t.Errorf("NewInitPayload().Token.NegTokenInit.MechTypes = %v, want %v", actual.Token.NegTokenInit.MechTypes, c.expected.Token.NegTokenInit.MechTypes)
			}

			for i, mechType := range actual.Token.NegTokenInit.MechTypes {
				if encoding_asn1.ObjectIdentifier(mechType).String() != encoding_asn1.ObjectIdentifier(c.expected.Token.NegTokenInit.MechTypes[i]).String() {
					t.Errorf("NewInitPayload().Token.NegTokenInit.MechTypes[%v] = %v, want %v", i, mechType, c.expected.Token.NegTokenInit.MechTypes[i])
				}
			}

			if hex.EncodeToString(actual.Token.NegTokenInit.MechListMIC) != hex.EncodeToString(c.expected.Token.NegTokenInit.MechListMIC) {
				t.Errorf("NewInitPayload().Token.NegTokenInit.MechListMIC = %v, want %v", actual.Token.NegTokenInit.MechListMIC, c.expected.Token.NegTokenInit.MechListMIC)
			}

			if hex.EncodeToString(actual.Token.NegTokenInit.NegHints) != hex.EncodeToString(c.expected.Token.NegTokenInit.NegHints) {
				t.Errorf("NewInitPayload().Token.NegTokenInit.NegHints = %v, want %v", actual.Token.NegTokenInit.NegHints, c.expected.Token.NegTokenInit.NegHints)
			}

			// TODO
		})
	}

}
