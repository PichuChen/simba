package simba

type CompressionAlgorithm uint16

const (
	// MS-SMB2 - v20211006 page 49/481
	SMB2_COMPRESSION_CAPABILITIES_NONE       CompressionAlgorithm = 0x0000
	SMB2_COMPRESSION_CAPABILITIES_LZNT1      CompressionAlgorithm = 0x0001
	SMB2_COMPRESSION_CAPABILITIES_LZ77       CompressionAlgorithm = 0x0002
	SMB2_COMPRESSION_CAPABILITIES_LZ77_HUFF  CompressionAlgorithm = 0x0003
	SMB2_COMPRESSION_CAPABILITIES_PATTERN_V1 CompressionAlgorithm = 0x0004
)

type CompressionCapability []byte

func (c CompressionCapability) CompressionAlgorithmCount() uint16 {
	return uint16(le.Uint16(c[0:2]))
}

func (c CompressionCapability) SetCompressionAlgorithmCount(v uint16) {
	le.PutUint16(c[0:2], v)
}

func (c CompressionCapability) CompressionAlgorithms() []CompressionAlgorithm {
	var res []CompressionAlgorithm
	for i := 0; i < int(c.CompressionAlgorithmCount()); i++ {
		res = append(res, CompressionAlgorithm(le.Uint16(c[4+i*2:6+i*2])))
	}
	return res
}
