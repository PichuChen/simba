package simba

import (
	"encoding/hex"
	"testing"
)

func TestSessionSetupRequest(t *testing.T) {

	cases := []struct {
		name     string
		input    []byte
		expected map[string]interface{}
	}{
		{
			name: "test",
			input: func() []byte {
				r, _ := hex.DecodeString("19000001000000000000000058004a000000000000000000604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000158288e2000000000000000000000000000000000a0000000000000f")
				return r
			}(),
			expected: map[string]interface{}{
				"StructureSize":        0x19,
				"Flags":                0,
				"SecurityMode":         SMB2_NEGOTIATE_SIGNING_ENABLED,
				"Capabilities":         0,
				"Channel":              0,
				"PreviousSessionId":    0,
				"SecurityBufferOffset": 0x58,
				"SecurityBufferLength": 74,
				"Buffer":               "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000158288e2000000000000000000000000000000000a0000000000000f",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ssr := SessionSetupRequest(c.input)
			if ssr.IsInvalid() {
				t.Errorf("SessionSetupRequest.IsInvalid() = true, want false")
			}
			if ssr.StructureSize() != uint16(c.expected["StructureSize"].(int)) {
				t.Errorf("SessionSetupRequest.StructureSize() = %v, want %v", ssr.StructureSize(), c.expected["StructureSize"])
			}
			if ssr.Flags() != SessionFlags(c.expected["Flags"].(int)) {
				t.Errorf("SessionSetupRequest.Flags() = %v, want %v", ssr.Flags(), c.expected["Flags"])
			}
			if ssr.SecurityMode() != (c.expected["SecurityMode"].(NegotiateSigning)) {
				t.Errorf("SessionSetupRequest.SecurityMode() = %v, want %v", ssr.SecurityMode(), c.expected["SecurityMode"])
			}
			if ssr.Capabilities() != Capabilities(c.expected["Capabilities"].(int)) {
				t.Errorf("SessionSetupRequest.Capabilities() = %v, want %v", ssr.Capabilities(), c.expected["Capabilities"])
			}
			if ssr.Channel() != uint32(c.expected["Channel"].(int)) {
				t.Errorf("SessionSetupRequest.Channel() = %v, want %v", ssr.Channel(), c.expected["Channel"])
			}
			if ssr.PreviousSessionId() != uint64(c.expected["PreviousSessionId"].(int)) {
				t.Errorf("SessionSetupRequest.PreviousSessionId() = %v, want %v", ssr.PreviousSessionId(), c.expected["PreviousSessionId"])
			}
			if ssr.SecurityBufferOffset() != uint16(c.expected["SecurityBufferOffset"].(int)) {
				t.Errorf("SessionSetupRequest.SecurityBufferOffset() = %v, want %v", ssr.SecurityBufferOffset(), c.expected["SecurityBufferOffset"])
			}
			if ssr.SecurityBufferLength() != uint16(c.expected["SecurityBufferLength"].(int)) {
				t.Errorf("SessionSetupRequest.SecurityBufferLength() = %v, want %v", ssr.SecurityBufferLength(), c.expected["SecurityBufferLength"])
			}
			if hex.EncodeToString(ssr.Buffer()) != c.expected["Buffer"].(string) {
				t.Errorf("SessionSetupRequest.Buffer() = %v, want %v", hex.EncodeToString(ssr.Buffer()), c.expected["Buffer"])
			}

			// TODO
		})
	}
}
