package simba

type HashAlgorithm uint16

const (
	// MS-SMB2 - v20211006 page 48/481
	SMB2_PREAUTH_INTEGRITY_SHA512 HashAlgorithm = 0x0001
)

type PreauthIntegrityCapability []byte

func (p PreauthIntegrityCapability) HashAlgorithmCount() uint16 {
	return le.Uint16(p[0:2])
}

func (p PreauthIntegrityCapability) SetHashAlgorithmCount(c uint16) {
	le.PutUint16(p[0:2], c)
}

func (p PreauthIntegrityCapability) SaltLength() uint16 {
	return le.Uint16(p[2:4])
}

func (p PreauthIntegrityCapability) SetSaltLength(l uint16) {
	le.PutUint16(p[2:4], l)
}

func (p PreauthIntegrityCapability) HashAlgorithms() []HashAlgorithm {
	var res []HashAlgorithm
	for i := 0; i < int(p.HashAlgorithmCount()); i++ {
		res = append(res, HashAlgorithm(le.Uint16(p[4+i*2:6+i*2])))
	}
	return res
}

func (p PreauthIntegrityCapability) SetHashAlgorithms(a []HashAlgorithm) {
	p.SetHashAlgorithmCount(uint16(len(a)))
	for i, v := range a {
		le.PutUint16(p[4+i*2:6+i*2], uint16(v))
	}
}

func (p PreauthIntegrityCapability) Salt() []byte {
	return p[4+int(p.HashAlgorithmCount())*2:]
}

func (p PreauthIntegrityCapability) SetSalt(s []byte) {
	p.SetSaltLength(uint16(len(s)))
	copy(p[4+int(p.HashAlgorithmCount())*2:], s)
}
