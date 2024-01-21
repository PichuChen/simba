package ntlmssp

import "encoding/binary"

type Version []byte

func (p Version) ProductMajorVersion() uint8 {
	return p[0]
}

func (p Version) SetProductMajorVersion(v uint8) {
	p[0] = v
}

func (p Version) ProductMinorVersion() uint8 {
	return p[1]
}

func (p Version) SetProductMinorVersion(v uint8) {
	p[1] = v
}

func (p Version) ProductBuild() uint16 {
	return binary.LittleEndian.Uint16(p[2:4])
}

func (p Version) SetProductBuild(v uint16) {
	binary.LittleEndian.PutUint16(p[2:4], v)
}

// Reserved for 3 bytes

// Should be NTLMSSP_REVISION_W2K3 (0x0F)
func (p Version) NTLMRevisionCurrent() uint8 {
	return p[7]
}

// Should be NTLMSSP_REVISION_W2K3 (0x0F)
func (p Version) SetNTLMRevisionCurrent(v uint8) {
	p[7] = v
}
