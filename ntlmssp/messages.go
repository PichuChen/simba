package ntlmssp

type NegotiateFlags uint32

const (
	// MS-NLMP v20220429 33/98
	NTLMSSP_NEGOTIATE_56                       NegotiateFlags = 1 << iota // aka W
	NTLMSSP_NEGOTIATE_KEY_EXCH                                            // aka V
	NTLMSSP_NEGOTIATE_128                                                 // aka U
	NTLMSSP_RESERVED1                                                     // aka r1
	NTLMSSP_RESERVED2                                                     // aka r2
	NTLMSSP_RESERVED3                                                     // aka r3
	NTLMSSP_NEGOTIATE_VERSION                                             // aka T
	NTLMSSP_RESERVED4                                                     // aka r4
	NTLMSSP_TARGET_INFO                                                   // aka S
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY                                    // aka R
	NTLMSSP_RESERVED5                                                     // aka r5
	NTLMSSP_NEGOTIATE_IDENTIFY                                            // aka Q
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY                            // aka P
	NTLMSSP_RESERVED6                                                     // aka r6
	NTLMSSP_TARGET_TYPE_SERVER                                            // aka O
	NTLMSSP_TARGET_TYPE_DOMAIN                                            // aka N
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN                                         // aka M
	NTLMSSP_RESERVED7                                                     // aka r7
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED                            // aka L
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED                                 // aka K
	NTLMSSP_NEGOTIATE_ANONYMOUS                                           // aka J
	NTLMSSP_RESERVED8                                                     // aka r8
	NTLMSSP_NEGOTIATE_NTLM                                                // aka H
	NTLMSSP_RESERVED9                                                     // aka r9
	NTLMSSP_NEGOTIATE_LM_KEY                                              // aka G
	NTLMSSP_NEGOTIATE_DATAGRAM                                            // aka F
	NTLMSSP_NEGOTIATE_SEAL                                                // aka E
	NTLMSSP_NEGOTIATE_SIGN                                                // aka D
	NTLMSSP_RESERVED10                                                    // aka r10
	NTLMSSP_REQUEST_TARGET                                                // aka C
	NTLMSSP_NEGOTIATE_OEM                                                 // aka B
	NTLMSSP_NEGOTIATE_UNICODE                                             // aka A
)

func NewChallengeMessage() {

}
