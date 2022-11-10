package simba

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestNegotiateRequest(t *testing.T) {

	cases := []struct {
		name     string
		input    []byte
		expected map[string]interface{}
	}{
		{
			name: "test",
			input: func() []byte {
				r, _ := hex.DecodeString("2400050001000000440000002c51da83fcb210b928e7cfd82ab2e9a870000000020000001103020300031002020200000100260000000000010020000100a7c3f2609f1852aa4b6ec3f093ff21ede8587383e88e5c633848e007066ff41e00000200060000000000020002000100")
				return r
			}(),
			expected: map[string]interface{}{
				"StructureSize":          0x24,
				"DialectCount":           5,
				"SecurityMode":           SMB2_NEGOTIATE_SIGNING_ENABLED,
				"Capabilities":           SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_ENCRYPTION,
				"ClientGuid":             "2c51da83fcb210b928e7cfd82ab2e9a8",
				"NegotiateContextOffset": 0x70,
				"NegotiateContextCount":  2,
				"Dialects": []Dialect{
					SMB2_DIALECT_311,
					SMB2_DIALECT_302,
					SMB2_DIALECT_30,
					SMB2_DIALECT_21,
					SMB2_DIALECT_202,
				},
				"NegotiateContextList": []ContextType{SMB2_PREAUTH_INTEGRITY_CAPABILITIES, SMB2_ENCRYPTION_CAPABILITIES},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nr := NegotiateRequest(c.input)
			if nr.IsInvalid() {
				t.Errorf("NegotiateRequest.IsInvalid() = true, want false")
			}
			if nr.StructureSize() != uint16(c.expected["StructureSize"].(int)) {
				t.Errorf("NegotiateRequest.StructureSize() = %v, want %v", nr.StructureSize(), c.expected["StructureSize"])
			}
			if nr.DialectCount() != uint16(c.expected["DialectCount"].(int)) {
				t.Errorf("NegotiateRequest.DialectCount() = %v, want %v", nr.DialectCount(), c.expected["DialectCount"])
			}
			if nr.SecurityMode() != c.expected["SecurityMode"].(NegotiateSigning) {
				t.Errorf("NegotiateRequest.SecurityMode() = %v, want %v", nr.SecurityMode(), c.expected["SecurityMode"])
			}
			if nr.Capabilities() != uint32(c.expected["Capabilities"].(Capabilities)) {
				t.Errorf("NegotiateRequest.Capabilities() = %v, want %v", nr.Capabilities(), c.expected["Capabilities"])
			}
			if fmt.Sprintf("%x", nr.ClientGuid()) != c.expected["ClientGuid"].(string) {
				t.Errorf("NegotiateRequest.ClientGuid() = %x, want %v", nr.ClientGuid(), c.expected["ClientGuid"])
			}
			if nr.NegotiateContextOffset() != uint32(c.expected["NegotiateContextOffset"].(int)) {
				t.Errorf("NegotiateRequest.NegotiateContextOffset() = %v, want %v", nr.NegotiateContextOffset(), c.expected["NegotiateContextOffset"])
			}
			if nr.NegotiateContextCount() != uint16(c.expected["NegotiateContextCount"].(int)) {
				t.Errorf("NegotiateRequest.NegotiateContextCount() = %v, want %v", nr.NegotiateContextCount(), c.expected["NegotiateContextCount"])
			}
			if len(nr.Dialects()) != len(c.expected["Dialects"].([]Dialect)) {
				t.Errorf("NegotiateRequest.Dialects() = %v, want %v", nr.Dialects(), c.expected["Dialects"])
			}
			for i, d := range nr.Dialects() {
				if d != c.expected["Dialects"].([]Dialect)[i] {
					t.Errorf("NegotiateRequest.Dialects() = %v, want %v", nr.Dialects(), c.expected["Dialects"])
				}
			}
			if len(nr.NegotiateContextList()) != len(c.expected["NegotiateContextList"].([]ContextType)) {
				t.Errorf("NegotiateRequest.NegotiateContextList() = %v, want %v", nr.NegotiateContextList(), c.expected["NegotiateContextList"])
			}
			for i, d := range nr.NegotiateContextList() {
				if d.ContextType() != c.expected["NegotiateContextList"].([]ContextType)[i] {
					t.Errorf("i: %d, d.ContextType() = %v d: %v, want %v", i, d.ContextType(), d, c.expected["NegotiateContextList"].([]ContextType)[i])
				}
			}

			// TODO
		})
	}
}
