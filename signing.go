package simba

type SingingAlgorithm uint16

const (
	// MS-SMB2 - v20211006 page 51/481
	SMB2_SIGNING_ALGORITHM_HMAC_SHA256 SingingAlgorithm = 0x0000
	SMB2_SIGNING_ALGORITHM_AES_CMAC    SingingAlgorithm = 0x0001
	SMB2_SIGNING_ALGORITHM_AES_GMAC    SingingAlgorithm = 0x0002
)

type SigningCapability []byte

func (c SigningCapability) SigningAlgorithmCount() uint16 {
	return uint16(le.Uint16(c[0:2]))
}

func (c SigningCapability) SetSigningAlgorithmCount(v uint16) {
	le.PutUint16(c[0:2], v)
}

func (c SigningCapability) SigningAlgorithms() []SingingAlgorithm {
	var res = make([]SingingAlgorithm, c.SigningAlgorithmCount())
	for i := 0; i < int(c.SigningAlgorithmCount()); i++ {
		res[i] = SingingAlgorithm(le.Uint16(c[4+i*2 : 6+i*2]))
	}
	return res
}

func (c SigningCapability) SetSigningAlgorithms(v []SingingAlgorithm) {
	c.SetSigningAlgorithmCount(uint16(len(v)))
	for i, t := range v {
		le.PutUint16(c[4+i*2:6+i*2], uint16(t))
	}
}
