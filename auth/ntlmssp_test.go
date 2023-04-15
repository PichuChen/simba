package auth

import (
	"encoding/hex"
	"testing"
)

func TestNTLMSSPDecode(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		expected map[string]interface{}
	}{
		{
			name: "test",
			input: func() []byte {
				r, _ := hex.DecodeString("4e544c4d5353500001000000158288e2000000000000000000000000000000000a0000000000000f")
				return r
			}(),
			expected: map[string]interface{}{
				"IsInvalid": false,
				"Flags": NTLMSSP_NEGOTIATE_56 |
					NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_VERSION |
					NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
					NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_SIGN |
					NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_UNICODE,
				"DomainNameLen":           uint16(0),
				"DomainNameMaxLen":        uint16(0),
				"DomainNameBufferOffset":  uint32(0),
				"WorkstationLen":          uint16(0),
				"WorkstationMaxLen":       uint16(0),
				"WorkstationBufferOffset": uint32(0),
				"MajorVersion":            uint8(10),
				"MinorVersion":            uint8(0),
				"BuildNumber":             uint16(0),
				"NTLMRevisionCurrent":     uint8(15),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nr := NTLMNegotiateMessage(c.input)
			if nr.IsInvalid() != c.expected["IsInvalid"].(bool) {
				t.Errorf("NTLMSSP.IsInvalid() = %v, want %v", nr.IsInvalid(), c.expected["IsInvalid"])
			}
			if nr.Flags() != c.expected["Flags"].(uint32) {
				t.Errorf("NTLMSSP.Flags() = %0x, want %0x", nr.Flags(), c.expected["Flags"])
			}
			if nr.DomainNameLen() != c.expected["DomainNameLen"].(uint16) {
				t.Errorf("NTLMSSP.DomainNameLen() = %v, want %v", nr.DomainNameLen(), c.expected["DomainNameLen"])
			}
			if nr.DomainNameMaxLen() != c.expected["DomainNameMaxLen"].(uint16) {
				t.Errorf("NTLMSSP.DomainNameMaxLen() = %v, want %v", nr.DomainNameMaxLen(), c.expected["DomainNameMaxLen"])
			}
			if nr.DomainNameBufferOffset() != c.expected["DomainNameBufferOffset"].(uint32) {
				t.Errorf("NTLMSSP.DomainNameBufferOffset() = %v, want %v", nr.DomainNameBufferOffset(), c.expected["DomainNameBufferOffset"])
			}
			if nr.WorkstationLen() != c.expected["WorkstationLen"].(uint16) {
				t.Errorf("NTLMSSP.WorkstationLen() = %v, want %v", nr.WorkstationLen(), c.expected["WorkstationLen"])
			}
			if nr.WorkstationMaxLen() != c.expected["WorkstationMaxLen"].(uint16) {
				t.Errorf("NTLMSSP.WorkstationMaxLen() = %v, want %v", nr.WorkstationMaxLen(), c.expected["WorkstationMaxLen"])
			}
			if nr.WorkstationBufferOffset() != c.expected["WorkstationBufferOffset"].(uint32) {
				t.Errorf("NTLMSSP.WorkstationBufferOffset() = %v, want %v", nr.WorkstationBufferOffset(), c.expected["WorkstationBufferOffset"])
			}
			if nr.MajorVersion() != c.expected["MajorVersion"].(uint8) {
				t.Errorf("NTLMSSP.MajorVersion() = %v, want %v", nr.MajorVersion(), c.expected["MajorVersion"])
			}
			if nr.MinorVersion() != c.expected["MinorVersion"].(uint8) {
				t.Errorf("NTLMSSP.MinorVersion() = %v, want %v", nr.MinorVersion(), c.expected["MinorVersion"])
			}
			if nr.BuildNumber() != c.expected["BuildNumber"].(uint16) {
				t.Errorf("NTLMSSP.BuildNumber() = %v, want %v", nr.BuildNumber(), c.expected["BuildNumber"])
			}
			if nr.NTLMRevisionCurrent() != c.expected["NTLMRevisionCurrent"].(uint8) {
				t.Errorf("NTLMSSP.NTLMRevisionCurrent() = %v, want %v", nr.NTLMRevisionCurrent(), c.expected["NTLMRevisionCurrent"])
			}
		})
	}
}
