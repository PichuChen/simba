package simba

type TransportFlag uint32

const (
	// MS-SMB2 - v20211006 page 50/481
	SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY TransportFlag = 0x00000001
)

type TransportCapability []byte

func (c TransportCapability) Capabilities() TransportFlag {
	return TransportFlag(le.Uint32(c[0:4]))
}

func (c TransportCapability) SetCapabilities(f TransportFlag) {
	le.PutUint32(c[0:4], uint32(f))
}
