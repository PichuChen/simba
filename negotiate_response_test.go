package simba

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestNegotiateResponse(t *testing.T) {

	cases := []struct {
		name     string
		input    []byte
		expected map[string]interface{}
	}{
		{
			name: "test",
			input: func() []byte {
				r, _ := hex.DecodeString("41000100110302003139322e3136382e352e3133350000000700000000008000000080000000800048f69555fcf4d801000000000000000080006000e0000000605e06062b0601050502a0543052a024302206092a864882f71201020206092a864886f712010202060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f726501002600000000000100200001007ef77bcacbac9320a00216936111a47899589c6dd49eb0c190b306a6cc84439d0000020004000000000001000100")
				return r
			}(),
			expected: map[string]interface{}{
				"StructureSize":   65,
				"SecurityMode":    1,
				"DialectRevision": SMB2_DIALECT_311,
				"ServerGuid":      "3139322e3136382e352e313335000000",
				"Capabilities":    7,
				"MaxTransactSize": 8388608,
				"MaxReadSize":     8388608,
				"MaxWriteSize":    8388608,
				"SystemTime": func() time.Time {
					r, _ := time.Parse("2006-01-02 15:04:05.999999999Z07:00", "2022-11-10 12:02:41.225684000+00:00")
					return r
				}(),
				"ServerStartTime":      time.Unix(0, 0),
				"SecurityBufferOffset": 0x80,
				"SecurityBufferLength": 96,
				"Buffer":               "605e06062b0601050502a0543052a024302206092a864882f71201020206092a864886f712010202060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265",
				"NegotiateContextList": []ContextType{
					SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
					SMB2_ENCRYPTION_CAPABILITIES,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nr := NegotiateResponse(c.input)
			if nr.IsInvalid() {
				t.Errorf("NegotiateResponse.IsInvalid() = true, want false")
			}
			if nr.StructureSize() != uint16(c.expected["StructureSize"].(int)) {
				t.Errorf("NegotiateResponse.StructureSize() = %v, want %v", nr.StructureSize(), c.expected["StructureSize"])
			}
			if nr.SecurityMode() != NegotiateSigning(c.expected["SecurityMode"].(int)) {
				t.Errorf("NegotiateResponse.SecurityMode() = %v, want %v", nr.SecurityMode(), c.expected["SecurityMode"])
			}
			if nr.DialectRevision() != Dialect(c.expected["DialectRevision"].(Dialect)) {
				t.Errorf("NegotiateResponse.DialectRevision() = %v, want %v", nr.DialectRevision(), c.expected["DialectRevision"])
			}
			if fmt.Sprintf("%x", nr.ServerGuid()) != c.expected["ServerGuid"].(string) {
				t.Errorf("NegotiateResponse.ServerGuid() = %x, want %v", nr.ServerGuid(), c.expected["ServerGuid"])
			}
			if nr.Capabilities() != Capabilities(c.expected["Capabilities"].(int)) {
				t.Errorf("NegotiateResponse.Capabilities() = %v, want %v", nr.Capabilities(), c.expected["Capabilities"])
			}
			if nr.MaxTransactSize() != uint32(c.expected["MaxTransactSize"].(int)) {
				t.Errorf("NegotiateResponse.MaxTransactSize() = %v, want %v", nr.MaxTransactSize(), c.expected["MaxTransactSize"])
			}
			if nr.MaxReadSize() != uint32(c.expected["MaxReadSize"].(int)) {
				t.Errorf("NegotiateResponse.MaxReadSize() = %v, want %v", nr.MaxReadSize(), c.expected["MaxReadSize"])
			}
			if nr.MaxWriteSize() != uint32(c.expected["MaxWriteSize"].(int)) {
				t.Errorf("NegotiateResponse.MaxWriteSize() = %v, want %v", nr.MaxWriteSize(), c.expected["MaxWriteSize"])
			}
			if nr.SystemTime().Unix() != c.expected["SystemTime"].(time.Time).Unix() {
				t.Errorf("NegotiateResponse.SystemTime() = %v, want %v", nr.SystemTime(), c.expected["SystemTime"])
			}
			// if nr.ServerStartTime().Unix() != c.expected["ServerStartTime"].(time.Time).Unix() {
			// 	t.Errorf("NegotiateResponse.ServerStartTime() = %v, want %v", nr.ServerStartTime(), c.expected["ServerStartTime"])
			// }
			if nr.SecurityBufferOffset() != uint16(c.expected["SecurityBufferOffset"].(int)) {
				t.Errorf("NegotiateResponse.SecurityBufferOffset() = %v, want %v", nr.SecurityBufferOffset(), c.expected["SecurityBufferOffset"])
			}
			if nr.SecurityBufferLength() != uint16(c.expected["SecurityBufferLength"].(int)) {
				t.Errorf("NegotiateResponse.SecurityBufferLength() = %v, want %v", nr.SecurityBufferLength(), c.expected["SecurityBufferLength"])
			}
			if fmt.Sprintf("%x", nr.Buffer()) != c.expected["Buffer"].(string) {
				t.Errorf("NegotiateResponse.Buffer() = %x, want %v", nr.Buffer(), c.expected["Buffer"])
			}

			if len(nr.NegotiateContexts()) != len(c.expected["NegotiateContextList"].([]ContextType)) {
				t.Errorf("NegotiateResponse.NegotiateContexts() = %v, want %v", nr.NegotiateContexts(), c.expected["NegotiateContextList"])
			}
			for i, v := range nr.NegotiateContexts() {
				if v.ContextType() != c.expected["NegotiateContextList"].([]ContextType)[i] {
					t.Errorf("NegotiateResponse.NegotiateContexts() = %v, want %v", nr.NegotiateContexts(), c.expected["NegotiateContextList"])
				}
			}

		})
	}
}
