package simba

import (
	"crypto/hmac"
	"crypto/sha256"
)

// r = 32, L = 128 if CipherID is 128CCM or 12GCM, L = 256 if CipherID is 256CCM or 256GCM
// MS-SMB2 3.1.4.2, PRF is HMAC-SHA256, KDF algorithm is Counter Mode
func smb3kdf(sessionKey []byte, label, context string) []byte {
	h := hmac.New(sha256.New, sessionKey)

	h.Write([]byte{0x00, 0x00, 0x00, 0x01}) // i = 1, r = 32
	h.Write([]byte(label))
	h.Write([]byte{0x00})
	h.Write([]byte(context))
	h.Write([]byte{0x00, 0x00, 0x00, 0x80}) // L = 128, r = 32

	return h.Sum(nil)[:16]

}
