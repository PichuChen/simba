package simba

import (
	"encoding/binary"
)

type SessionSetupRequest []byte

func (p SessionSetupRequest) IsInvalid() bool {
	// MS-SMB2, MUST be set to 25
	if len(p) < 25 {
		return true
	}

	return false
}

func (p SessionSetupRequest) StructureSize() uint16 {
	return binary.LittleEndian.Uint16(p[0:2])
}

func (p SessionSetupRequest) SetStructureSize() {
	binary.LittleEndian.PutUint16(p[0:2], 25)
}

func (p SessionSetupRequest) Flags() SessionFlags {
	return SessionFlags(p[2])
}

func (p SessionSetupRequest) SetFlags(v SessionFlags) {
	p[2] = uint8(v)
}

func (p SessionSetupRequest) SecurityMode() NegotiateSigning {
	return NegotiateSigning(p[3])
}

func (p SessionSetupRequest) SetSecurityMode(v NegotiateSigning) {
	p[3] = uint8(v)
}

func (p SessionSetupRequest) Capabilities() Capabilities {
	return Capabilities(binary.LittleEndian.Uint32(p[4:8]))
}

func (p SessionSetupRequest) SetCapabilities(v Capabilities) {
	binary.LittleEndian.PutUint32(p[4:8], uint32(v))
}

func (p SessionSetupRequest) Channel() uint32 {
	return binary.LittleEndian.Uint32(p[8:12])
}

func (p SessionSetupRequest) SetChannel(v uint32) {
	binary.LittleEndian.PutUint32(p[8:12], v)
}

func (p SessionSetupRequest) SecurityBufferOffset() uint16 {
	return binary.LittleEndian.Uint16(p[12:14])
}

func (p SessionSetupRequest) SetSecurityBufferOffset(v uint16) {
	binary.LittleEndian.PutUint16(p[12:14], v)
}

func (p SessionSetupRequest) SecurityBufferLength() uint16 {
	return binary.LittleEndian.Uint16(p[14:16])
}

func (p SessionSetupRequest) SetSecurityBufferLength(v uint16) {
	binary.LittleEndian.PutUint16(p[14:16], v)
}

func (p SessionSetupRequest) PreviousSessionId() uint64 {
	return binary.LittleEndian.Uint64(p[16:24])
}

func (p SessionSetupRequest) SetPreviousSessionId(v uint64) {
	binary.LittleEndian.PutUint64(p[16:24], v)
}

func (p SessionSetupRequest) Buffer() []byte {
	offset := p.SecurityBufferOffset() - 64
	return p[offset : offset+p.SecurityBufferLength()]
}

func (p SessionSetupRequest) SetBuffer(v []byte) {
	if len(v) > 0 {
		p.SetSecurityBufferOffset(20 + 64)
		p.SetSecurityBufferLength(uint16(len(v)))
		copy(p[20:], v)
	}
}
