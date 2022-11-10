package simba

import (
	"encoding/binary"
	"log"
)

type NegotiateRequest []byte

func (p NegotiateRequest) IsInvalid() bool {
	// MS-SMB2, MUST be set to 36
	if len(p) < 36 {
		return true
	}

	return false
}

func (p NegotiateRequest) StructureSize() uint16 {
	return binary.LittleEndian.Uint16(p[0:2])
}

func (p NegotiateRequest) SetStructureSize() {
	binary.LittleEndian.PutUint16(p[0:2], 36)
}

func (p NegotiateRequest) DialectCount() uint16 {
	return binary.LittleEndian.Uint16(p[2:4])
}

func (p NegotiateRequest) SetDialectCount(v uint16) {
	binary.LittleEndian.PutUint16(p[2:4], v)
}

func (p NegotiateRequest) SecurityMode() NegotiateSigning {
	return NegotiateSigning(binary.LittleEndian.Uint16(p[4:6]))
}

func (p NegotiateRequest) SetSecurityMode(v NegotiateSigning) {
	binary.LittleEndian.PutUint16(p[4:6], uint16(v))
}

func (p NegotiateRequest) Capabilities() uint32 {
	return binary.LittleEndian.Uint32(p[8:12])
}

func (p NegotiateRequest) SetCapabilities(v uint32) {
	binary.LittleEndian.PutUint32(p[8:12], v)
}

func (p NegotiateRequest) ClientGuid() []byte {
	return p[12:28]
}

func (p NegotiateRequest) SetClientGuid(v []byte) {
	copy(p[12:28], v)
}

func (p NegotiateRequest) NegotiateContextOffset() uint32 {
	return binary.LittleEndian.Uint32(p[28:32])

}

func (p NegotiateRequest) SetNegotiateContextOffset(v uint32) {
	binary.LittleEndian.PutUint32(p[28:32], v)
}

func (p NegotiateRequest) NegotiateContextCount() uint16 {
	return binary.LittleEndian.Uint16(p[32:34])
}

func (p NegotiateRequest) SetNegotiateContextCount(v uint16) {
	binary.LittleEndian.PutUint16(p[32:34], v)
}

func (p NegotiateRequest) Dialects() []Dialect {
	if p.DialectCount() > 5 {
		log.Fatal("DialectCount > 5")
		return nil
	}
	dialects := make([]Dialect, p.DialectCount())
	for i := 0; i < int(p.DialectCount()); i++ {
		dialects[i] = Dialect(binary.LittleEndian.Uint16(p[36+i*2 : 36+i*2+2]))
	}
	return dialects
}

func (p NegotiateRequest) SetDialects(v []Dialect) {
	for i := 0; i < len(v); i++ {
		binary.LittleEndian.PutUint16(p[36+i*2:36+i*2+2], uint16(v[i]))
	}
}

func (p NegotiateRequest) NegotiateContextList() []NegotiateContext {
	offset := p.NegotiateContextOffset() - 64
	if offset > uint32(len(p)) {
		log.Fatalf("NegotiateContextOffset > len(p) %d > %d", offset, len(p))
		return nil
	}
	count := p.NegotiateContextCount()
	if count == 0 {
		return nil
	}
	contexts := make([]NegotiateContext, count)
	for i := 0; i < int(count); i++ {
		if offset > uint32(len(p)) {
			log.Fatalf("num:%d, NegotiateContextOffset > len(p) %d > %d", i, offset, len(p))
			return nil
		}
		contexts[i] = NegotiateContext(p[offset:])
		offset += uint32(contexts[i].DataLength()) + 8
		if offset%8 != 0 {
			offset += 8 - offset%8
		}
	}
	return contexts
}
