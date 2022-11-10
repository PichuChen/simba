package simba

import (
	"log"
	"time"
)

type NegotiateSigning uint16

const (
	// MS-SMB2 - v20211006 page 53/481
	SMB2_NEGOTIATE_SIGNING_ENABLED  NegotiateSigning = 0x0001
	SMB2_NEGOTIATE_SIGNING_REQUIRED NegotiateSigning = 0x0002
)

type Capabilities uint32

const (
	// MS-SMB2 - v20211006 page 53/481
	SMB2_GLOBAL_CAP_DFS                Capabilities = 0x00000001
	SMB2_GLOBAL_CAP_LEASING            Capabilities = 0x00000002
	SMB2_GLOBAL_CAP_LARGE_MTU          Capabilities = 0x00000004
	SMB2_GLOBAL_CAP_MULTI_CHANNEL      Capabilities = 0x00000008
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES Capabilities = 0x00000010
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING  Capabilities = 0x00000020
	SMB2_GLOBAL_CAP_ENCRYPTION         Capabilities = 0x00000040
)

type NegotiateResponse []byte

func (p NegotiateResponse) IsInvalid() bool {
	// MS-SMB2, MUST be set to 36
	if len(p) < 36 {
		return true
	}

	return false
}

func (r NegotiateResponse) StructureSize() uint16 {
	return le.Uint16(r[0:2])
}

func (r NegotiateResponse) SetStructureSize(v uint16) {
	le.PutUint16(r[0:2], v)
}

func (r NegotiateResponse) SecurityMode() NegotiateSigning {
	return NegotiateSigning(le.Uint16(r[2:4]))
}

func (r NegotiateResponse) SetSecurityMode(v NegotiateSigning) {
	le.PutUint16(r[2:4], uint16(v))
}

func (r NegotiateResponse) DialectRevision() Dialect {
	return Dialect(le.Uint16(r[4:6]))
}

func (r NegotiateResponse) SetDialectRevision(v Dialect) {
	le.PutUint16(r[4:6], uint16(v))
}

func (r NegotiateResponse) NegotiateContextCount() uint16 {
	return le.Uint16(r[6:8])
}

func (r NegotiateResponse) SetNegotiateContextCount(v uint16) {
	le.PutUint16(r[6:8], v)
}

func (r NegotiateResponse) ServerGuid() []byte {
	return r[8:24]
}

func (r NegotiateResponse) SetServerGuid(v []byte) {
	copy(r[8:24], v)
}

func (r NegotiateResponse) Capabilities() Capabilities {
	return Capabilities(le.Uint32(r[24:28]))
}

func (r NegotiateResponse) SetCapabilities(v Capabilities) {
	le.PutUint32(r[24:28], uint32(v))
}

func (r NegotiateResponse) MaxTransactSize() uint32 {
	return le.Uint32(r[28:32])
}

func (r NegotiateResponse) SetMaxTransactSize(v uint32) {
	le.PutUint32(r[28:32], v)
}

func (r NegotiateResponse) MaxReadSize() uint32 {
	return le.Uint32(r[32:36])
}

func (r NegotiateResponse) SetMaxReadSize(v uint32) {
	le.PutUint32(r[32:36], v)
}

func (r NegotiateResponse) MaxWriteSize() uint32 {
	return le.Uint32(r[36:40])
}

func (r NegotiateResponse) SetMaxWriteSize(v uint32) {
	le.PutUint32(r[36:40], v)
}

func (r NegotiateResponse) SystemTime() time.Time {
	dwLowDateTime := le.Uint32(r[40:44])
	dwHighDateTime := le.Uint32(r[44:48])
	dateTime := uint64(dwHighDateTime)<<32 | uint64(dwLowDateTime)
	return time.Unix(0, int64(dateTime-116444736000000000)*100)
}

func (r NegotiateResponse) SetSystemTime(v time.Time) {
	dateTime := v.UnixNano()/100 + 116444736000000000
	dwLowDateTime := uint32(dateTime)
	dwHighDateTime := uint32(dateTime >> 32)
	le.PutUint32(r[40:44], dwLowDateTime)
	le.PutUint32(r[44:48], dwHighDateTime)
}

func (r NegotiateResponse) ServerStartTime() time.Time {
	dwLowDateTime := le.Uint32(r[48:52])
	dwHighDateTime := le.Uint32(r[52:56])
	dateTime := uint64(dwHighDateTime)<<32 | uint64(dwLowDateTime)
	return time.Unix(0, int64(dateTime-116444736000000000)*100)
}

func (r NegotiateResponse) SetServerStartTime(v time.Time) {
	dateTime := v.UnixNano()/100 + 116444736000000000
	dwLowDateTime := uint32(dateTime)
	dwHighDateTime := uint32(dateTime >> 32)
	le.PutUint32(r[48:52], dwLowDateTime)
	le.PutUint32(r[52:56], dwHighDateTime)
}

func (r NegotiateResponse) SecurityBufferOffset() uint16 {
	return le.Uint16(r[56:58])
}

func (r NegotiateResponse) SetSecurityBufferOffset(v uint16) {
	le.PutUint16(r[56:58], v)
}

func (r NegotiateResponse) SecurityBufferLength() uint16 {
	return le.Uint16(r[58:60])
}

func (r NegotiateResponse) SetSecurityBufferLength(v uint16) {
	le.PutUint16(r[58:60], v)
}

// 3.1.1 only
func (r NegotiateResponse) NegotiateContextOffset() uint32 {
	return le.Uint32(r[60:64])
}

// 3.1.1 only
func (r NegotiateResponse) SetNegotiateContextOffset(v uint32) {
	le.PutUint32(r[60:64], v)
}

func (r NegotiateResponse) Buffer() []byte {
	offset := r.SecurityBufferOffset() - 64
	length := r.SecurityBufferLength()
	if offset+length > uint16(len(r)) {
		log.Printf("warning: negotiate response buffer is out of bounds (offset=%d, length=%d, len=%d)", offset, length, len(r))
		return nil
	}
	return r[offset : offset+length]
}

func (r NegotiateResponse) SetBuffer(v []byte) {
	offset := r.SecurityBufferOffset() - 64
	length := r.SecurityBufferLength()
	copy(r[offset:offset+length], v)
}

func (r NegotiateResponse) NegotiateContexts() []NegotiateContext {
	offset := r.NegotiateContextOffset() - 64
	length := r.NegotiateContextCount()
	if offset > uint32(len(r)) {
		log.Printf("warning: negotiate response negotiate contexts are out of bounds")
		return nil
	}
	ret := make([]NegotiateContext, length)
	for i := uint16(0); i < length; i++ {
		if offset > uint32(len(r)) {
			log.Printf("warning: negotiate response negotiate context is out of bounds")
			return nil
		}
		ret[i] = NegotiateContext(r[offset:])
		length := uint32(ret[i].DataLength())
		ret[i] = NegotiateContext(r[offset : offset+length+8])
		offset += 8 + uint32(length)
		if offset%8 != 0 {
			offset += 8 - offset%8
		}
	}
	return ret
}

func (r NegotiateResponse) SetNegotiateContexts(v []NegotiateContext) {
	offset := r.NegotiateContextOffset() - 64
	for _, c := range v {
		length := uint32(c.DataLength())
		copy(r[offset:offset+length+8], c)
		offset += 8 + uint32(length)
		if offset%8 != 0 {
			offset += 8 - offset%8
		}
	}
}
