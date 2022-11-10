package simba

import "encoding/binary"

type PacketCodec []byte

func (p PacketCodec) IsInvalid() bool {
	// MS-SMB2, MUST be set to 64
	if len(p) < 64 {
		return true
	}

	// check if the packet is a valid SMB2 packet
	// MS-SMB2, MUST be set to 0xFE, 'S', 'M', 'B'
	if p[0] != 0xfe || p[1] != 0x53 || p[2] != 0x4d || p[3] != 0x42 {
		return true
	}
	return false
}

func (p PacketCodec) ProtocolId() []byte {
	return p[:4]
}

func (p PacketCodec) SetProtocolId() {
	copy(p[:4], []byte{0xfe, 0x53, 0x4d, 0x42})
}

func (p PacketCodec) StructureSize() uint16 {
	return binary.LittleEndian.Uint16(p[4:6])
}

func (p PacketCodec) SetStructureSize() {
	binary.LittleEndian.PutUint16(p[4:6], 64)
}

func (p PacketCodec) CreditCharge() uint16 {
	return binary.LittleEndian.Uint16(p[6:8])
}

func (p PacketCodec) SetCreditCharge(v uint16) {
	binary.LittleEndian.PutUint16(p[6:8], v)
}

// In SMB 3.x, this field is ChannelSequence field followed by Reserved field
func (p PacketCodec) ChannelSequence() uint16 {
	return binary.LittleEndian.Uint16(p[8:10])
}

func (p PacketCodec) SetChannelSequence(v uint16) {
	binary.LittleEndian.PutUint16(p[8:10], v)
}

func (p PacketCodec) Reserved() uint16 {
	return binary.LittleEndian.Uint16(p[10:12])
}

func (p PacketCodec) SetReserved(v uint16) {
	binary.LittleEndian.PutUint16(p[10:12], v)
}

// In SMB 2.0.2 and SMB 2.1 dialects, this field is Status field
func (p PacketCodec) Status() uint32 {
	return binary.LittleEndian.Uint32(p[8:12])
}

func (p PacketCodec) SetStatus(v uint32) {
	binary.LittleEndian.PutUint32(p[8:12], v)
}

func (p PacketCodec) Command() Command {
	return Command(binary.LittleEndian.Uint16(p[12:14]))
}

func (p PacketCodec) SetCommand(v Command) {
	binary.LittleEndian.PutUint16(p[12:14], uint16(v))
}

func (p PacketCodec) CreditRequestResponse() uint16 {
	return binary.LittleEndian.Uint16(p[14:16])
}

func (p PacketCodec) SetCreditRequestResponse(v uint16) {
	binary.LittleEndian.PutUint16(p[14:16], v)
}

func (p PacketCodec) Flags() uint32 {
	return binary.LittleEndian.Uint32(p[16:20])
}

func (p PacketCodec) SetFlags(v uint32) {
	binary.LittleEndian.PutUint32(p[16:20], v)
}

func (p PacketCodec) NextCommand() uint32 {
	return binary.LittleEndian.Uint32(p[20:24])
}

func (p PacketCodec) SetNextCommand(v uint32) {
	binary.LittleEndian.PutUint32(p[20:24], v)
}

func (p PacketCodec) MessageId() uint64 {
	return binary.LittleEndian.Uint64(p[24:32])
}

func (p PacketCodec) SetMessageId(v uint64) {
	binary.LittleEndian.PutUint64(p[24:32], v)
}

// If the SMB2_FLAGS_ASYNC_COMMAND flag is set in the Flags field, this field will be AsyncId
func (p PacketCodec) AsyncId() uint64 {
	return binary.LittleEndian.Uint64(p[32:40])
}

// If SMB2_FLAGS_ASYNC_COMMAND set
func (p PacketCodec) SetAsyncId(v uint64) {
	binary.LittleEndian.PutUint64(p[32:40], v)
}

// If SMB2_FLAGS_ASYNC_COMMAND not set
func (p PacketCodec) TreeId() uint32 {
	return binary.LittleEndian.Uint32(p[36:40])
}

func (p PacketCodec) SetTreeId(v uint32) {
	binary.LittleEndian.PutUint32(p[36:40], v)
}

func (p PacketCodec) SessionId() uint64 {
	return binary.LittleEndian.Uint64(p[40:48])
}

func (p PacketCodec) SetSessionId(v uint64) {
	binary.LittleEndian.PutUint64(p[40:48], v)
}

func (p PacketCodec) Signature() []byte {
	return p[48:64]
}

func (p PacketCodec) SetSignature(v []byte) {
	copy(p[48:64], v)
}
