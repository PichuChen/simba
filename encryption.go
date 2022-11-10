package simba

type Cipher uint16

const (
	// MS-SMB2 - v20211006 page 48/481
	SMB2_ENCRYPTION_AES128_CCM Cipher = 0x0001
	SMB2_ENCRYPTION_AES128_GCM Cipher = 0x0002
	SMB2_ENCRYPTION_AES256_CCM Cipher = 0x0003
	SMB2_ENCRYPTION_AES256_GCM Cipher = 0x0004
)

func (c Cipher) String() string {
	switch c {
	case SMB2_ENCRYPTION_AES128_CCM:
		return "SMB2_ENCRYPTION_AES128_CCM"
	case SMB2_ENCRYPTION_AES128_GCM:
		return "SMB2_ENCRYPTION_AES128_GCM"
	case SMB2_ENCRYPTION_AES256_CCM:
		return "SMB2_ENCRYPTION_AES256_CCM"
	case SMB2_ENCRYPTION_AES256_GCM:
		return "SMB2_ENCRYPTION_AES256_GCM"
	}
	return "Unknown"
}

type EncryptionCapability []byte

func (e EncryptionCapability) CipherCount() uint16 {
	return uint16(le.Uint16(e[0:2]))
}

func (e EncryptionCapability) SetCipherCount(c uint16) {
	le.PutUint16(e[0:2], c)
}

func (e EncryptionCapability) Ciphers() []Cipher {
	var res []Cipher
	for i := 0; i < int(e.CipherCount()); i++ {
		res = append(res, Cipher(le.Uint16(e[4+i*2:6+i*2])))
	}
	return res
}
