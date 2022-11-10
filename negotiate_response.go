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
	return time.Unix(0, int64(le.Uint64(r[40:48])))
}

func (r NegotiateResponse) SetSystemTime(v time.Time) {
	le.PutUint64(r[40:48], uint64(v.UnixNano()))
}

func (r NegotiateResponse) ServerStartTime() time.Time {
	return time.Unix(0, int64(le.Uint64(r[48:56])))
}

func (r NegotiateResponse) SetServerStartTime(v time.Time) {
	le.PutUint64(r[48:56], uint64(v.UnixNano()))
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
	offset := r.SecurityBufferOffset()
	length := r.SecurityBufferLength()
	if offset+length > uint16(len(r)) {
		log.Printf("warning: negotiate response buffer is out of bounds")
		return nil
	}
	return r[offset : offset+length]
}

func (r NegotiateResponse) SetBuffer(v []byte) {
	offset := r.SecurityBufferOffset()
	length := r.SecurityBufferLength()
	copy(r[offset:offset+length], v)
}

func (r NegotiateResponse) NegotiateContexts() []NegotiateContext {
	offset := r.NegotiateContextOffset()
	length := r.NegotiateContextCount()
	if offset > uint32(len(r)) {
		log.Printf("warning: negotiate response negotiate contexts are out of bounds")
		return nil
	}
	ret := make([]NegotiateContext, length)
	for i := uint16(0); i < length; i++ {
		ret[i] = NegotiateContext(r[offset:])
		length := uint32(ret[i].DataLength())
		ret[i] = NegotiateContext(r[offset : offset+length])
		offset += 8 + uint32(length)
		if offset > uint32(len(r)) {
			log.Printf("warning: negotiate response negotiate context is out of bounds")
			return nil
		}
	}
	return ret
}

func (r NegotiateResponse) SetNegotiateContexts(v []NegotiateContext) {
	offset := r.NegotiateContextOffset()
	for _, c := range v {
		length := uint32(c.DataLength())
		copy(r[offset:offset+length], c)
		offset += 8 + uint32(length)
	}
}
