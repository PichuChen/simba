package simba

import (
	"encoding/binary"
)

type SessionSetupResponse []byte

type SessionSetupSessionFlags uint16

const (
	// MS-SMB2 - v20211006 page 57/481
	SMB2_SESSION_FLAG_IS_GUEST     SessionSetupSessionFlags = 0x0001
	SMB2_SESSION_FLAG_IS_NULL      SessionSetupSessionFlags = 0x0002
	SMB2_SESSION_FLAG_ENCRYPT_DATA SessionSetupSessionFlags = 0x0004
)

func (p SessionSetupResponse) IsInvalid() bool {
	// MS-SMB2, MUST be set to 8
	if len(p) < 8 {
		return true
	}

	return false
}

func (p SessionSetupResponse) StructureSize() uint16 {
	return binary.LittleEndian.Uint16(p[0:2])
}

func (p SessionSetupResponse) SetStructureSize() {
	binary.LittleEndian.PutUint16(p[0:2], 9)
}

func (p SessionSetupResponse) SessionFlags() SessionSetupSessionFlags {
	return SessionSetupSessionFlags(binary.LittleEndian.Uint16(p[2:4]))
}

func (p SessionSetupResponse) SetSessionFlags(v SessionSetupSessionFlags) {
	binary.LittleEndian.PutUint16(p[2:4], uint16(v))
}

func (p SessionSetupResponse) SecurityBufferOffset() uint16 {
	return binary.LittleEndian.Uint16(p[4:6])
}

func (p SessionSetupResponse) SetSecurityBufferOffset(v uint16) {
	binary.LittleEndian.PutUint16(p[4:6], v)
}

func (p SessionSetupResponse) SecurityBufferLength() uint16 {
	return binary.LittleEndian.Uint16(p[6:8])
}

func (p SessionSetupResponse) SetSecurityBufferLength(v uint16) {
	binary.LittleEndian.PutUint16(p[6:8], v)
}

func (p SessionSetupResponse) Buffer() []byte {
	return p[p.SecurityBufferOffset()-64 : p.SecurityBufferOffset()+p.SecurityBufferLength()]
}

func (p SessionSetupResponse) SetBuffer(v []byte) {
	// p.SetSecurityBufferOffset(8)
	offset := p.SecurityBufferOffset() - 64
	length := p.SecurityBufferLength()
	copy(p[offset:offset+length], v)
}
