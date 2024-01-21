package ntlmssp

import "encoding/binary"

type ChallengeMessage []byte

func (p ChallengeMessage) IsInvalid() bool {
	// MS-NLMP, Signature, MUST be set to NTLMSSP
	if len(p) < 40 {
		return true
	}

	if string(p[0:8]) != "NTLMSSP\x00" {
		return true
	}
	// Check MessageType == 2
	if p[8] != 2 {
		return true
	}

	return false
}

func (p ChallengeMessage) TargetName() string {
	// Check TargetNameLen
	if len(p) < 20 {
		return ""
	}

	targetNameLen := binary.LittleEndian.Uint16(p[12:14])
	targetNameMaxLen := binary.LittleEndian.Uint16(p[14:16])
	targetNameBufferOffset := binary.LittleEndian.Uint32(p[16:20])

	if targetNameLen == 0 || targetNameMaxLen == 0 || targetNameBufferOffset == 0 {
		return ""
	}

	buf := p[targetNameBufferOffset : targetNameBufferOffset+uint32(targetNameLen)]
	return string(buf) // TODO: unicode

}

func (p ChallengeMessage) SetTargetName(input string) {
	// Check TargetNameLen
	if len(p) < 20 {
		return
	}

	inputLen := len(input)

	targetNameLen := binary.LittleEndian.Uint16(p[12:14])
	targetNameMaxLen := binary.LittleEndian.Uint16(p[14:16])
	targetNameBufferOffset := binary.LittleEndian.Uint32(p[16:20])

	if targetNameLen == 0 || targetNameMaxLen == 0 || targetNameBufferOffset == 0 {
		return
	}

	if inputLen > int(targetNameMaxLen) {
		// it will waste original buffer space and leak original buffer data
		targetNameBufferOffset = uint32(len(p))
		p = append(p, make([]byte, inputLen)...)
		binary.LittleEndian.PutUint32(p[16:20], targetNameBufferOffset)
	}
	// allocate new buffer
	binary.LittleEndian.PutUint16(p[12:14], uint16(inputLen))
	binary.LittleEndian.PutUint16(p[14:16], uint16(inputLen)) // on the MS-NLMP - v20220429, this field SHOULD be set to the same value as TargetNameLen
	buf := p[targetNameBufferOffset : targetNameBufferOffset+uint32(targetNameLen)]
	copy(buf, input) // TODO: unicode
}

func (p ChallengeMessage) NegotiateFlags() NegotiateFlags {
	return NegotiateFlags(binary.LittleEndian.Uint32(p[20:24]))
}

func (p ChallengeMessage) SetNegotiateFlags(v NegotiateFlags) {
	binary.LittleEndian.PutUint32(p[20:24], uint32(v))
}

func (p ChallengeMessage) ServerChallenge() []byte {
	return p[24:32]
}

func (p ChallengeMessage) SetServerChallenge(v []byte) {
	copy(p[24:32], v)
}

func (p ChallengeMessage) Reserved() []byte {
	return p[32:40]
}

func (p ChallengeMessage) SetReserved(v []byte) {
	copy(p[32:40], v)
}

func (p ChallengeMessage) TargetInfo() []byte {
	// Check TargetInfoLen
	if len(p) < 48 {
		return []byte{}
	}

	targetInfoLen := binary.LittleEndian.Uint16(p[40:42])
	targetInfoMaxLen := binary.LittleEndian.Uint16(p[42:44])
	targetInfoBufferOffset := binary.LittleEndian.Uint32(p[44:48])

	if targetInfoLen == 0 || targetInfoMaxLen == 0 || targetInfoBufferOffset == 0 {
		return []byte{}
	}

	return p[targetInfoBufferOffset : targetInfoBufferOffset+uint32(targetInfoLen)]
}

func (p ChallengeMessage) SetTargetInfo(v []byte) {
	// Check TargetInfoLen
	if len(p) < 48 {
		return
	}

	inputLen := len(v)

	targetInfoLen := binary.LittleEndian.Uint16(p[40:42])
	targetInfoMaxLen := binary.LittleEndian.Uint16(p[42:44])
	targetInfoBufferOffset := binary.LittleEndian.Uint32(p[44:48])

	if targetInfoLen == 0 || targetInfoMaxLen == 0 || targetInfoBufferOffset == 0 {
		return
	}

	if inputLen > int(targetInfoMaxLen) {
		// it will waste original buffer space and leak original buffer data
		targetInfoBufferOffset = uint32(len(p))
		p = append(p, make([]byte, inputLen)...)
		binary.LittleEndian.PutUint32(p[44:48], targetInfoBufferOffset)
	}
	// allocate new buffer
	binary.LittleEndian.PutUint16(p[40:42], uint16(inputLen))
	binary.LittleEndian.PutUint16(p[42:44], uint16(inputLen)) // on the MS-NLMP - v20220429, this field SHOULD be set to the same value as TargetInfoLen
	buf := p[targetInfoBufferOffset : targetInfoBufferOffset+uint32(targetInfoLen)]
	copy(buf, v)
}

func (p ChallengeMessage) Version() Version {
	return Version(p[48:56])
}

func (p ChallengeMessage) SetVersion(v Version) {
	binary.LittleEndian.PutUint64(p[48:56], uint64(v))
}
