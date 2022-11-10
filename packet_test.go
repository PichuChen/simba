package simba

import (
	"encoding/hex"
	"testing"
)

func TestPacket(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		expected map[string]interface{}
	}{
		{
			name: "test",
			input: func() []byte {
				r, _ := hex.DecodeString("fe534d424000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400050001000000440000002c51da83fcb210b928e7cfd82ab2e9a870000000020000001103020300031002020200000100260000000000010020000100a7c3f2609f1852aa4b6ec3f093ff21ede8587383e88e5c633848e007066ff41e00000200060000000000020002000100")
				return r
			}(),
			expected: map[string]interface{}{
				"ProtocolID":    "fe534d42",
				"StructureSize": 64,
				"CreditCharge":  1,
				"Status":        0,
				"Command":       0,
				"Credits":       1,
				"Flags":         0,
				"NextCommand":   0,
				"MessageID":     0,
				"Reserved":      0,
				"TreeID":        0,
				"SessionID":     0,
				"Signature":     "00000000000000000000000000000000",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nr := PacketCodec(c.input)
			if nr.IsInvalid() {
				t.Errorf("NegotiateRequest.IsInvalid() = true, want false")
			}
			if got := hex.EncodeToString(nr.ProtocolId()); got != c.expected["ProtocolID"] {
				t.Errorf("NegotiateRequest.ProtocolId() = %v, want %v", got, c.expected["ProtocolID"])
			}
			if nr.StructureSize() != uint16(c.expected["StructureSize"].(int)) {
				t.Errorf("NegotiateRequest.StructureSize() = %d, want %d", nr.StructureSize(), c.expected["StructureSize"])
			}
			if nr.CreditCharge() != uint16(c.expected["CreditCharge"].(int)) {
				t.Errorf("NegotiateRequest.CreditCharge() = %v, want %v", nr.CreditCharge(), c.expected["CreditCharge"])
			}
			if nr.Status() != uint32(c.expected["Status"].(int)) {
				t.Errorf("NegotiateRequest.Status() = %v, want %v", nr.Status(), c.expected["Status"])
			}
			if nr.Command() != Command(c.expected["Command"].(int)) {
				t.Errorf("NegotiateRequest.Command() = %v, want %v", nr.Command(), c.expected["Command"])
			}
			if nr.CreditRequestResponse() != uint16(c.expected["Credits"].(int)) {
				t.Errorf("NegotiateRequest.Credits() = %v, want %v", nr.CreditRequestResponse(), c.expected["Credits"])
			}
			if nr.Flags() != uint32(c.expected["Flags"].(int)) {
				t.Errorf("NegotiateRequest.Flags() = %v, want %v", nr.Flags(), c.expected["Flags"])
			}
			if nr.NextCommand() != uint32(c.expected["NextCommand"].(int)) {
				t.Errorf("NegotiateRequest.NextCommand() = %v, want %v", nr.NextCommand(), c.expected["NextCommand"])
			}
			if nr.MessageId() != uint64(c.expected["MessageID"].(int)) {
				t.Errorf("NegotiateRequest.MessageId() = %v, want %v", nr.MessageId(), c.expected["MessageID"])
			}

			if nr.TreeId() != uint32(c.expected["TreeID"].(int)) {
				t.Errorf("NegotiateRequest.TreeId() = %v, want %v", nr.TreeId(), c.expected["TreeID"])
			}
			if nr.SessionId() != uint64(c.expected["SessionID"].(int)) {
				t.Errorf("NegotiateRequest.SessionId() = %v, want %v", nr.SessionId(), c.expected["SessionID"])
			}
			if got := hex.EncodeToString(nr.Signature()); got != c.expected["Signature"] {
				t.Errorf("NegotiateRequest.Signature() = %v, want %v", got, c.expected["Signature"])
			}

			// TODO
		})
	}
}
