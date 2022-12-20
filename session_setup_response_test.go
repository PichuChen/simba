package simba

import (
	"encoding/hex"
	"testing"
)

func TestSessionSetupResponse(t *testing.T) {

	cases := []struct {
		name     string
		input    []byte
		expected map[string]interface{}
	}{
		{
			name: "test",
			input: func() []byte {
				r, _ := hex.DecodeString("0900000000000000")
				return r
			}(),
			expected: map[string]interface{}{
				"StructureSize":        0x09,
				"SessionFlags":         0,
				"SecurityBufferOffset": 0x0,
				"SecurityBufferLength": 0,
				"Buffer":               "",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ssr := SessionSetupResponse(c.input)
			if ssr.IsInvalid() {
				t.Errorf("SessionSetupRequest.IsInvalid() = true, want false")
			}
			if ssr.StructureSize() != uint16(c.expected["StructureSize"].(int)) {
				t.Errorf("SessionSetupRequest.StructureSize() = %v, want %v", ssr.StructureSize(), c.expected["StructureSize"])
			}
			if ssr.SessionFlags() != SessionSetupSessionFlags(c.expected["SessionFlags"].(int)) {
				t.Errorf("SessionSetupRequest.SessionFlags() = %v, want %v", ssr.SessionFlags(), c.expected["SessionFlags"])
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
