package auth

import (
	"encoding/binary"
	"strings"
)

type NTLMMessage []byte

const (
	NTLMSSP_NEGOTIATE uint32 = 1
	NTLMSSP_AUTH      uint32 = 3
)

func (p NTLMMessage) IsInvalid() bool {
	// MS-SMB2, MUST be set to 12
	if len(p) < 12 {
		return true
	}

	if strings.Compare("NTLMSSP", string(p[0:7])) != 0 {
		return true
	}

	return false
}

func (p NTLMMessage) MessageType() uint32 {
	return binary.LittleEndian.Uint32(p[8:12])
}

func (p NTLMMessage) SetMessageType(v uint32) {
	binary.LittleEndian.PutUint32(p[8:12], v)
}

type NTLMNegotiateMessage []byte

func (p NTLMNegotiateMessage) IsInvalid() bool {
	if len(p) < 32 {
		return true
	}

	return false
}

func (p NTLMNegotiateMessage) Flags() uint32 {
	return binary.LittleEndian.Uint32(p[12:16])
}

func (p NTLMNegotiateMessage) SetFlags(v uint32) {
	binary.LittleEndian.PutUint32(p[12:16], v)
}

func (p NTLMNegotiateMessage) DomainNameLen() uint16 {
	return binary.LittleEndian.Uint16(p[16:18])
}

func (p NTLMNegotiateMessage) SetDomainNameLen(v uint16) {
	binary.LittleEndian.PutUint16(p[16:18], v)
}

func (p NTLMNegotiateMessage) DomainNameMaxLen() uint16 {
	return binary.LittleEndian.Uint16(p[18:20])
}

func (p NTLMNegotiateMessage) SetDomainNameMaxLen(v uint16) {
	binary.LittleEndian.PutUint16(p[18:20], v)
}

func (p NTLMNegotiateMessage) DomainNameBufferOffset() uint32 {
	return binary.LittleEndian.Uint32(p[20:24])
}

func (p NTLMNegotiateMessage) SetDomainNameBufferOffset(v uint32) {
	binary.LittleEndian.PutUint32(p[20:24], v)
}

func (p NTLMNegotiateMessage) WorkstationLen() uint16 {
	return binary.LittleEndian.Uint16(p[24:26])
}

func (p NTLMNegotiateMessage) SetWorkstationLen(v uint16) {
	binary.LittleEndian.PutUint16(p[24:26], v)
}

func (p NTLMNegotiateMessage) WorkstationMaxLen() uint16 {
	return binary.LittleEndian.Uint16(p[26:28])
}

func (p NTLMNegotiateMessage) SetWorkstationMaxLen(v uint16) {
	binary.LittleEndian.PutUint16(p[26:28], v)
}

func (p NTLMNegotiateMessage) WorkstationBufferOffset() uint32 {
	return binary.LittleEndian.Uint32(p[28:32])
}

func (p NTLMNegotiateMessage) SetWorkstationBufferOffset(v uint32) {
	binary.LittleEndian.PutUint32(p[28:32], v)
}

func (p NTLMNegotiateMessage) MajorVersion() uint8 {
	return p[32]
}

func (p NTLMNegotiateMessage) MinorVersion() uint8 {
	return p[33]
}

func (p NTLMNegotiateMessage) BuildNumber() uint16 {
	return binary.LittleEndian.Uint16(p[34:36])
}

func (p NTLMNegotiateMessage) SetBuildNumber(v uint16) {
	binary.LittleEndian.PutUint16(p[34:36], v)
}

func (p NTLMNegotiateMessage) VersionReserved() []byte {
	return p[36:39]
}

func (p NTLMNegotiateMessage) NTLMRevisionCurrent() uint8 {
	// NTLMSSP_REVISION_W2K3 = 0x0F
	return p[39]
}
