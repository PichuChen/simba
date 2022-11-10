package simba

type ContextType uint16

const (
	// MS-SMB2 - v20211006 page 47/481
	SMB2_PREAUTH_INTEGRITY_CAPABILITIES ContextType = 0x0001
	SMB2_ENCRYPTION_CAPABILITIES        ContextType = 0x0002
	SMB2_COMPRESSION_CAPABILITIES       ContextType = 0x0003
	SMB2_NETNAME_NEGOTIATE_CONTEXT_ID   ContextType = 0x0005
	SMB2_TRANSPORT_CAPABILITIES         ContextType = 0x0006
	SMB2_RDMA_TRANSFORM_CAPABILITIES    ContextType = 0x0007
	SMB2_SIGNING_CAPABILITIES           ContextType = 0x0008
)

func (c ContextType) String() string {
	switch c {
	case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
		return "SMB2_PREAUTH_INTEGRITY_CAPABILITIES"
	case SMB2_ENCRYPTION_CAPABILITIES:
		return "SMB2_ENCRYPTION_CAPABILITIES"
	case SMB2_COMPRESSION_CAPABILITIES:
		return "SMB2_COMPRESSION_CAPABILITIES"
	case SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:
		return "SMB2_NETNAME_NEGOTIATE_CONTEXT_ID"
	case SMB2_TRANSPORT_CAPABILITIES:
		return "SMB2_TRANSPORT_CAPABILITIES"
	case SMB2_RDMA_TRANSFORM_CAPABILITIES:
		return "SMB2_RDMA_TRANSFORM_CAPABILITIES"
	case SMB2_SIGNING_CAPABILITIES:
		return "SMB2_SIGNING_CAPABILITIES"
	}
	return "Unknown"
}

type NegotiateContext []byte

func (c NegotiateContext) ContextType() ContextType {
	return ContextType(le.Uint16(c[0:2]))
}

func (c NegotiateContext) SetContextType(t ContextType) {
	le.PutUint16(c[0:2], uint16(t))
}

func (c NegotiateContext) DataLength() uint16 {
	return le.Uint16(c[2:4])
}

func (c NegotiateContext) SetDataLength(l uint16) {
	le.PutUint16(c[2:4], l)
}

func (c NegotiateContext) Reserved() uint32 {
	return le.Uint32(c[4:8])
}

func (c NegotiateContext) SetReserved(r uint32) {
	le.PutUint32(c[4:8], r)
}

func (c NegotiateContext) Data() []byte {
	return c[8:]
}

func (c NegotiateContext) SetData(d []byte) {
	copy(c[8:], d)
}
