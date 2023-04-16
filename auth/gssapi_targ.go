package auth

import (
	encoding_asn1 "encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type TargPayload struct {
	NegResult     uint8
	SupportedMech MechType
	ResponseToken []byte
	MechListMIC   []byte
}

func NewTargPayload(b []byte) (*TargPayload, error) {
	var input = cryptobyte.String(b)
	var inner = cryptobyte.String{}
	var outPresent bool
	var intValue int
	ret := &TargPayload{}
	// a181c4
	if !input.ReadASN1(&inner, 0xa1) {
		return nil, fmt.Errorf("ReadASN1 for tag 0x%0x failed", 0xa1)
	}
	// 3081c1
	var seq cryptobyte.String
	if !inner.ReadASN1(&seq, asn1.SEQUENCE) {
		return nil, fmt.Errorf("ReadASN1 for tag 0x%0x failed", asn1.SEQUENCE)
	}

	// a003
	if !seq.ReadOptionalASN1(&inner, &outPresent, 0xa0) {
		return nil, fmt.Errorf("ReadASN1 for negResult 0x%0x failed", 0xa0)
	}

	if outPresent {
		// 0a0101
		if !inner.ReadASN1Enum(&intValue) {
			return nil, fmt.Errorf("ReadASN1Bytes for negResult value 0x%0x failed", 0x0a)
		}
		ret.NegResult = uint8(intValue)
	}

	// a10c
	if !seq.ReadOptionalASN1(&inner, &outPresent, 0xa1) {
		return nil, fmt.Errorf("ReadASN1 for supportedMech 0x%0x failed", 0xa1)
	}

	if outPresent {
		// 060a2b06010401823702020a
		oid := encoding_asn1.ObjectIdentifier{}
		if !inner.ReadASN1ObjectIdentifier(&oid) {
			return nil, fmt.Errorf("ReadASN1ObjectIdentifier for supportedMech oid failed")
		}
		ret.SupportedMech = MechType(oid)
	}

	// a281ab
	if !seq.ReadOptionalASN1(&inner, &outPresent, 0xa2) {
		return nil, fmt.Errorf("ReadASN1 for responseToken 0x%0x failed", 0xa2)
	}

	if outPresent {
		// 0481a84e5 44c4d5353500002000000140014003800000015828ae2b5bdb4abf704918f00000000000000005c005c004c000000060100000000000f4d00420056004d00320032003100320030003800020014004d00420056004d00320032003100320030003800010014004d00420056004d0032003200310032003000380004000000030014006d00620076006d003200320031003200300038000700080060bbda0f486dd90100000000
		if !inner.ReadASN1Bytes(&ret.ResponseToken, asn1.OCTET_STRING) {
			return nil, fmt.Errorf("ReadASN1Bytes responseToken failed")
		}
	}

	// a300
	if !seq.ReadOptionalASN1(&inner, &outPresent, 0xa3) {
		return nil, fmt.Errorf("ReadASN1 for mechListMIC 0x%0x failed", 0xa3)
	}

	if outPresent {
		// 0400
		if !inner.ReadASN1Bytes(&ret.MechListMIC, asn1.OCTET_STRING) {
			return nil, fmt.Errorf("ReadASN1Bytes mechListMIC failed")
		}
	}

	return ret, nil
}

func (payload *TargPayload) Bytes() ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddASN1(0xA1, func(builder *cryptobyte.Builder) {
		builder.AddASN1(asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
			builder.AddASN1(0xA0, func(builder *cryptobyte.Builder) {
				builder.AddASN1Enum(int64(payload.NegResult))
			})

			builder.AddASN1(0xA1, func(builder *cryptobyte.Builder) {
				builder.AddASN1ObjectIdentifier(encoding_asn1.ObjectIdentifier(payload.SupportedMech))
			})

			if len(payload.ResponseToken) > 0 {
				builder.AddASN1(0xA2, func(builder *cryptobyte.Builder) {
					builder.AddASN1OctetString(payload.ResponseToken)
				})
			}

			if len(payload.MechListMIC) > 0 {
				builder.AddASN1(0xA3, func(builder *cryptobyte.Builder) {
					builder.AddASN1OctetString(payload.MechListMIC)
				})
			}
		})
	})
	return builder.Bytes()
}
