package simba

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKDF(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		labal    string
		context  string
		expected []byte
	}{
		{
			name: "case 1",
			input: func() []byte {
				r, _ := hex.DecodeString("7CD451825D0450D235424E44BA6E78CC")
				return r
			}(),
			labal:   "SMB2AESCMAC\x00",
			context: "SmbSign\x00",
			expected: func() []byte {
				r, _ := hex.DecodeString("0B7E9C5CAC36C0F6EA9AB275298CEDCE")
				return r
			}(),
		},
		{
			name: "case 2",
			input: func() []byte {
				r, _ := hex.DecodeString("7CD451825D0450D235424E44BA6E78CC")
				return r
			}(),
			labal:   "SMB2APP\x00",
			context: "SmbRpc\x00",
			expected: func() []byte {
				r, _ := hex.DecodeString("BB23A4575AA26C721AF525AF15A87B4F")
				return r
			}(),
		},
		{
			name: "case 3",
			input: func() []byte {
				r, _ := hex.DecodeString("7CD451825D0450D235424E44BA6E78CC")
				return r
			}(),
			labal:   "SMB2AESCCM\x00",
			context: "ServerIn \x00",
			expected: func() []byte {
				r, _ := hex.DecodeString("FAD27796665B313EBB578F388632B4F7")
				return r
			}(),
		},
		{
			name: "case 4",
			input: func() []byte {
				r, _ := hex.DecodeString("7CD451825D0450D235424E44BA6E78CC")
				return r
			}(),
			labal:   "SMB2AESCCM\x00",
			context: "ServerOut\x00",
			expected: func() []byte {
				r, _ := hex.DecodeString("B0F0427F7CEB416D1D9DCC0CD4F99447")
				return r
			}(),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual := smb3kdf(c.input, c.labal, c.context)
			if !bytes.Equal(actual, c.expected) {
				t.Errorf("expected %0x, actual %0x", c.expected, actual)
			}
		})
	}

}
