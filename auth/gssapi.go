package auth

import (
	encoding_asn1 "encoding/asn1"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	OBJECT_IDENTIFIER = 0x06
)

var DefaultNegoPayload = func() []byte {
	r, _ := hex.DecodeString("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265")

	return r
}()

type InitPayload struct {
	OID   encoding_asn1.ObjectIdentifier `asn1:"set,tag:6"`
	Token NegotiationToken               `asn1:"set,tag:0"`
}

// RFC 4178 - 4.2. NegotiationToken

// NegotiationToken ::= CHOICE {
// 	negTokenInit    [0] NegTokenInit,
// 	negTokenResp    [1] NegTokenResp
// }

type NegotiationToken struct {
	NegTokenInit NegTokenInitData `asn1:"application,tag:0"`
	// NegTokenResp *NegTokenResp
}

// RFC 4178 - 4.2.1.  NegTokenInit
// NegTokenInit ::= SEQUENCE {
// 	mechTypes       [0] MechTypeList,
// 	reqFlags        [1] ContextFlags  OPTIONAL,
// 	  -- inherited from RFC 2478 for backward compatibility,
// 	  -- RECOMMENDED to be left out
// 	mechToken       [2] OCTET STRING  OPTIONAL,
// 	mechListMIC     [3] OCTET STRING  OPTIONAL,
// 	...
// }

type NegTokenInitData struct {
	MechTypes   MechTypeList            `asn1:"application,tag:0"`
	ReqFlags    encoding_asn1.BitString `asn1:"application,tag:1"`
	MechToken   []byte                  `asn1:"application,tag:2"`
	NegHints    []byte                  `asn1:"application,tag:3"`
	MechListMIC []byte                  `asn1:"application,tag:3"`
}

type ContextFlags int32

// var (
// 	DELEG_FLAG    ContextFlags = 0
// 	MUTUAL_FLAG   ContextFlags = 1
// 	REPLAY_FLAG   ContextFlags = 2
// 	SEQUENCE_FLAG ContextFlags = 3
// 	ANNO_FLAG     ContextFlags = 4
// 	CONF_FLAG     ContextFlags = 5
// 	INTEG_FLAG    ContextFlags = 6
// )

// RFC 4178 - 4.2.2.  NegTokenResp

type MechTypeList []MechType

type MechType encoding_asn1.ObjectIdentifier

func NewInitPayload(b []byte) (*InitPayload, error) {
	var input = cryptobyte.String(b)
	var inner = cryptobyte.String{}
	ret := &InitPayload{}

	if !input.ReadASN1(&inner, asn1.Tag(0).Constructed()|0x40 /* application */) {
		return nil, fmt.Errorf("ReadASN1 for tag %v failed", asn1.Tag(0).Constructed()|0x40)
	}

	if !inner.ReadASN1ObjectIdentifier(&ret.OID) {
		return nil, fmt.Errorf("ReadASN1ObjectIdentifier failed")
	}

	var SPNObjectString = cryptobyte.String{}
	var SPNObjectStringInner = cryptobyte.String{}
	if !inner.ReadASN1(&SPNObjectString, 0xA0 /* asn1.ClassContextSpecific */) ||
		!SPNObjectString.ReadASN1(&SPNObjectStringInner, asn1.SEQUENCE) {
		return nil, fmt.Errorf("ReadASN1 for SPNObjectString tag %v failed", 0xA0)
	}

	var MechTypesInner = cryptobyte.String{}
	var MechTypeInner = cryptobyte.String{}
	if !SPNObjectStringInner.ReadASN1(&MechTypesInner, 0xA0 /* asn1.ClassContextSpecific */) ||
		!MechTypesInner.ReadASN1(&MechTypeInner, asn1.SEQUENCE) {
		return nil, fmt.Errorf("cryptobyte.String(%v).ReadASN1(&actual, asn1.ClassContextSpecific, 0) = false; want true", b)
	}

	list := MechTypeList{}
	for !MechTypeInner.Empty() {
		// var mechType = MechType{}
		oid := encoding_asn1.ObjectIdentifier{}
		if !MechTypeInner.ReadASN1ObjectIdentifier(&oid) {
			return nil, fmt.Errorf("ReadASN1ObjectIdentifier failed")
		}
		list = append(list, MechType(oid))
	}

	ret.Token.NegTokenInit.MechTypes = list

	// fmt.Println("remain: ", MechTypeInner)
	// fmt.Println("remain: ", MechTypesInner)
	var outPresent bool
	var reqFlagInner = cryptobyte.String{}
	if !SPNObjectStringInner.ReadOptionalASN1(&reqFlagInner, &outPresent, 0xA1 /* asn1.ClassContextSpecific */) {
		return nil, fmt.Errorf("ReadASN1 for SPNObjectString tag %v failed", 0xA1)
	}
	if outPresent {
		var reqFlag = encoding_asn1.BitString{}
		if !reqFlagInner.ReadASN1BitString(&reqFlag) {
			return nil, fmt.Errorf("ReadASN1BitString with tag 1 failed")
		}
		ret.Token.NegTokenInit.ReqFlags = reqFlag
	}

	var mechTokenInner = cryptobyte.String{}
	if !SPNObjectStringInner.ReadOptionalASN1(&mechTokenInner, &outPresent, 0xA2 /* asn1.ClassContextSpecific */) {
		return nil, fmt.Errorf("ReadASN1 for SPNObjectString tag %v failed", 0xA2)
	}
	if outPresent {
		var mechToken = []byte{}
		if !mechTokenInner.ReadASN1Bytes(&mechToken, asn1.OCTET_STRING) {
			return nil, fmt.Errorf("ReadASN1Bytes with tag 2 failed")
		}
		ret.Token.NegTokenInit.MechToken = mechToken
	}
	// fmt.Println("remain: ", SPNObjectStringInner)

	var mechListMICInner = cryptobyte.String{}
	if !SPNObjectStringInner.ReadOptionalASN1(&mechListMICInner, &outPresent, 0xA3 /* asn1.ClassContextSpecific */) {
		return nil, fmt.Errorf("ReadASN1 for SPNObjectString tag %v failed", 0xA3)
	}
	if outPresent {
		// fmt.Printf("mechListMICInner: %v\n", mechListMICInner)
		// fmt.Printf("mechListMICInner: %s\n", mechListMICInner)
		var mechListMIC = []byte{}
		var tag asn1.Tag
		var inner = cryptobyte.String{}
		if mechListMICInner.ReadAnyASN1Element(&inner, &tag) {
			if tag == asn1.OCTET_STRING {
				// is MechListMIC
				if !inner.ReadASN1Bytes(&mechListMIC, asn1.OCTET_STRING) {
					return nil, fmt.Errorf("ReadASN1Bytes failed")
				}
			} else if tag == asn1.SEQUENCE {
				var negHints = cryptobyte.String{}
				if !inner.ReadASN1(&negHints, asn1.SEQUENCE) {
					return nil, fmt.Errorf("ReadASN1 for SPNObjectString tag %v failed", 0xA3)
				}
				var negHintsInner = cryptobyte.String{}
				if !negHints.ReadASN1(&negHintsInner, 0xA0) {
					return nil, fmt.Errorf("ReadASN1 for SPNObjectString tag %v failed", 0xA0)
				}
				// fmt.Printf("negHintsInner2: %v\n", negHintsInner)
				var negHintsBytes []byte
				if !negHintsInner.ReadASN1Bytes(&negHintsBytes, asn1.GeneralString) { // asn1.GeneralString
					return nil, fmt.Errorf("ReadASN1 for SPNObjectString tag %v failed", 0xA3)
				}
				ret.Token.NegTokenInit.NegHints = negHintsBytes

			} else {
				return nil, fmt.Errorf("tag is not asn1.OCTET_STRING")
			}
		}
		ret.Token.NegTokenInit.MechListMIC = mechListMIC
	}
	// fmt.Println("remain: ", SPNObjectStringInner)

	var negHintsInner = cryptobyte.String{}
	// if there are more than 3 optional fields, the negHints will be the 3th field, and the mechListMIC will be the 4th field
	if !SPNObjectStringInner.ReadOptionalASN1(&negHintsInner, &outPresent, 0xA4 /* asn1.ClassContextSpecific */) {
		return nil, fmt.Errorf("ReadASN1 for SPNObjectString tag %v failed", 0xA4)
	}
	if outPresent {
		var inner = []byte{}
		if !negHintsInner.ReadASN1Bytes(&inner, asn1.OCTET_STRING) {
			return nil, fmt.Errorf("ReadASN1Bytes failed")
		}
		ret.Token.NegTokenInit.MechListMIC = inner
	}

	// fmt.Println("remain: ", SPNObjectStringInner)
	// fmt.Println("remain: ", SPNObjectString)

	return ret, nil
}

func (payload *InitPayload) Bytes() ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddASN1(asn1.Tag(0).Constructed()|0x40, func(builder *cryptobyte.Builder) {
		builder.AddASN1ObjectIdentifier(payload.OID)
		builder.AddASN1(0xA0, func(builder *cryptobyte.Builder) {
			builder.AddASN1(asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
				builder.AddASN1(0xA0, func(builder *cryptobyte.Builder) {
					builder.AddASN1(asn1.SEQUENCE, func(builder *cryptobyte.Builder) {
						for _, mechType := range payload.Token.NegTokenInit.MechTypes {
							builder.AddASN1ObjectIdentifier(encoding_asn1.ObjectIdentifier(mechType))
						}
					})
				})

				if payload.Token.NegTokenInit.ReqFlags.BitLength > 0 {
					builder.AddASN1(0xA1, func(builder *cryptobyte.Builder) {
						builder.AddASN1BitString(payload.Token.NegTokenInit.ReqFlags.Bytes)
					})
				}

				if len(payload.Token.NegTokenInit.MechToken) > 0 {
					builder.AddASN1(0xA2, func(builder *cryptobyte.Builder) {
						builder.AddASN1OctetString(payload.Token.NegTokenInit.MechToken)
					})
				}

				if len(payload.Token.NegTokenInit.NegHints) > 0 {
					builder.AddASN1(0xA3, func(builder *cryptobyte.Builder) {
						builder.AddASN1(asn1.SEQUENCE+1, func(builder *cryptobyte.Builder) {
							builder.AddASN1(0xA0, func(builder *cryptobyte.Builder) {
								builder.AddASN1(asn1.GeneralString, func(builder *cryptobyte.Builder) {
									builder.AddBytes(payload.Token.NegTokenInit.NegHints)
								})
							})
						})
					})
				}
			})
		})

	})
	return builder.Bytes()
}
