package simba

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/PichuChen/simba/auth"
)

var serverGUID = []byte{0x6d, 0x62, 0x76, 0x6d, 0x32, 0x32, 0x31, 0x32, 0x30, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

type conn struct {
	server *Server

	// rwc is the underlying network connection.
	rwc net.Conn

	remoteAddr string
}

type response struct {
	conn *conn
}

func (srv *Server) Serve(l net.Listener) error {
	for {
		rw, err := l.Accept()
		if err != nil {

			return err
		}
		fmt.Printf("Accept a new connection: %v\n", rw)
		c := srv.newConn(rw)
		go c.serve()
	}
}

func (srv *Server) newConn(rw net.Conn) *conn {
	c := &conn{
		server: srv,
		rwc:    rw,
	}
	return c
}

func (c *conn) serve() {
	fmt.Printf("remote addr: %v\n", c.rwc.RemoteAddr())
	c.remoteAddr = c.rwc.RemoteAddr().String()

	defer c.rwc.Close()

	for {
		r, err := c.readRequest()
		if err != nil {
			fmt.Printf("readRequest error: %v\n", err)
			return
		}
		fmt.Printf("readRequest: %v\n", r)

		switch r.Command() {
		case SMB2_NEGOTIATE:
			fmt.Printf("SMB2_NEGOTIATE\n")
			msg := NegotiateRequest(r[64:])
			c.handleNegotiate(r, msg)
		case SMB2_SESSION_SETUP:
			fmt.Printf("SMB2_SESSION_SETUP\n")
			msg := SessionSetupRequest(r[64:])
			c.handleSessionSetup(r, msg)

		default:
			fmt.Printf("unknown command: %v (%d)\n", r.Command(), r.Command())
		}
	}

}

func (c *conn) readRequest() (w PacketCodec, err error) {
	var buf [1024]byte
	n, err := c.rwc.Read(buf[:])
	if err != nil {
		return nil, err
	}

	// From NetBIOS
	fmt.Printf("readRequest: %v len: %d\n", hex.EncodeToString(buf[:n]), n)
	// zero := buf[0]
	stringProtocolLength := (uint32(buf[1]) << 16) + (uint32(buf[2]) << 8) + uint32(buf[3])
	// TODO: using loop to read all data
	if n < int(stringProtocolLength) {
		n2, err := c.rwc.Read(buf[n:])
		if err != nil {
			return nil, err
		}
		n += n2
	}

	smb2Message := buf[4 : 4+stringProtocolLength]

	msg := PacketCodec(smb2Message)
	fmt.Printf("msg: len: %d data: %+v\n", len(msg), msg)
	if msg.IsInvalid() {
		fmt.Printf("msg is invalid\n")
		return nil, fmt.Errorf("msg is invalid")
	}

	fmt.Printf("msg type: %v\n", msg.Command())

	return msg, nil

}

func (c *conn) handleNegotiate(p PacketCodec, msg NegotiateRequest) error {
	fmt.Printf("handleNegotiate: %v\n", msg.ClientGuid())

	securityBufferPayload := auth.DefaultNegoPayload

	negotiateContextPreauth := NegotiateContext(make([]byte, 8+38))
	negotiateContextPreauth.SetContextType(SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
	negotiateContextPreauth.SetDataLength(38)
	negotiateContextPreauth.SetReserved(0)
	negotiateContextPreauth.SetData([]byte{
		0x01, 0x00, // hash algorithm count
		0x20, 0x00, // salt length
		0x01, 0x00, // hash algorithm: SHA-512
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20})

	negotiateContextEncryption := NegotiateContext(make([]byte, 8+4))
	negotiateContextEncryption.SetContextType(SMB2_ENCRYPTION_CAPABILITIES)
	negotiateContextEncryption.SetDataLength(4)
	negotiateContextEncryption.SetReserved(0)
	negotiateContextEncryption.SetData([]byte{0x01, 0x00, 0x02, 0x00})

	pkt := []byte{}
	responseHdr := NegotiateResponse(make([]byte, 65+len(securityBufferPayload)+len(negotiateContextPreauth)+19))
	responseHdr.SetStructureSize(65)
	responseHdr.SetSecurityMode(SMB2_NEGOTIATE_SIGNING_ENABLED)
	responseHdr.SetDialectRevision(0x311)
	responseHdr.SetNegotiateContextCount(2)
	responseHdr.SetServerGuid(serverGUID)
	responseHdr.SetCapabilities(SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_LARGE_MTU)
	responseHdr.SetMaxTransactSize(8388608) // 8MB
	responseHdr.SetMaxReadSize(8388608)
	responseHdr.SetMaxWriteSize(8388608)
	responseHdr.SetSystemTime(time.Now())
	responseHdr.SetServerStartTime(time.Time{})
	responseHdr.SetSecurityBufferOffset(0x80)
	responseHdr.SetSecurityBufferLength(uint16(len(securityBufferPayload)))
	responseHdr.SetBuffer(securityBufferPayload)

	responseHdr.SetNegotiateContextOffset(0xD0)
	responseHdr.SetNegotiateContexts([]NegotiateContext{negotiateContextPreauth, negotiateContextEncryption})

	smb2Header := PacketCodec(make([]byte, 64, 64))
	smb2Header.SetProtocolId()
	smb2Header.SetStructureSize()
	smb2Header.SetCreditCharge(1)
	smb2Header.SetCommand(SMB2_NEGOTIATE)
	smb2Header.SetStatus(0)
	smb2Header.SetCreditRequestResponse(1)
	smb2Header.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	smb2Header.SetNextCommand(0)
	smb2Header.SetMessageId(p.MessageId())
	smb2Header.SetTreeId(0)
	smb2Header.SetSessionId(p.SessionId())
	smb2Header.SetSignature([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	l := len(smb2Header) + len(responseHdr)
	netBIOSHeader := []byte{0x00, 0x00, 0x00, 0x00}
	netBIOSHeader[3] = byte(l)
	netBIOSHeader[2] = byte(l >> 8)

	// smb2Header := []byte{0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	pkt = append(pkt, netBIOSHeader...)
	pkt = append(pkt, smb2Header...)
	pkt = append(pkt, responseHdr...)
	// pkt = append(pkt, responseBody...)

	fmt.Printf("handleNegotiate: %v\n", hex.EncodeToString(pkt))
	c.rwc.Write(pkt)
	fmt.Printf("send response: %d\n", len(pkt))

	return nil

}

func (c *conn) handleSessionSetup(p PacketCodec, msg SessionSetupRequest) error {
	fmt.Printf("handleSessionSetup: %v\n", msg)

	// get NTLMSSP message
	gssBuffer := msg.Buffer()
	var mechToken []byte
	if gssBuffer[0] == 0x60 {
		gssPayload, err := auth.NewInitPayload(gssBuffer)
		if err != nil {
			log.Printf("handleSessionSetup NewInitPayload: %v", err)
			return fmt.Errorf("handleSessionSetup NewInitPayload: %v", err)
		}
		mechToken = gssPayload.Token.NegTokenInit.MechToken
	} else if gssBuffer[0] == 0xa1 {
		gssPayload, err := auth.NewTargPayload(gssBuffer)
		if err != nil {
			log.Printf("handleSessionSetup NewTargPayload: %v", err)
			return fmt.Errorf("handleSessionSetup NewTargPayload: %v", err)
		}
		mechToken = gssPayload.ResponseToken

	}

	// get NTLMSSP message
	fmt.Printf("mechToken: %v\n", hex.EncodeToString(mechToken))

	ntlmsspPayload := auth.NTLMMessage(mechToken)
	if ntlmsspPayload.IsInvalid() {
		return fmt.Errorf("handleSessionSetup NTLMMessage is invalid")
	}

	switch ntlmsspPayload.MessageType() {
	case auth.NTLMSSP_NEGOTIATE:
		log.Printf("NTLM_NEGOTIATE: %v\n", len(ntlmsspPayload))
		return c.handleSessionSetupNtmlsspNetotiate(p, msg, auth.NTLMNegotiateMessage(mechToken))
	case auth.NTLMSSP_AUTH:
		log.Printf("NTLMSSP_AUTH: %v\n", len(ntlmsspPayload))
		return c.handleSessionSetupNtmlsspAuth(p, msg, auth.NTLMNegotiateMessage(mechToken))
	default:
		fmt.Printf("NTLMSSP unknown message type: %0x\n", ntlmsspPayload.MessageType())
		// case auth.NTLM_CHALLENGE:
		// 	fmt.Printf("NTLM_CHALLENGE: %v\n", ntlmsspPayload)
		// case auth.NTLM_AUTHENTICATE:
		// 	fmt.Printf("NTLM_AUTHENTICATE: %v\n", ntlmsspPayload)
	}
	return fmt.Errorf("unknown ntlm message type: %0x\n", ntlmsspPayload.MessageType())
}
func (c *conn) handleSessionSetupNtmlsspNetotiate(p PacketCodec, msg SessionSetupRequest, ntlpPayload auth.NTLMNegotiateMessage) error {

	pkt := []byte{}
	securityBuffer, _ := hex.DecodeString("a181c43081c1a0030a0101a10c060a2b06010401823702020aa281ab0481a84e544c4d5353500002000000140014003800000015828ae2b5bdb4abf704918f00000000000000005c005c004c000000060100000000000f4d00420056004d00320032003100320030003800020014004d00420056004d00320032003100320030003800010014004d00420056004d0032003200310032003000380004000000030014006d00620076006d003200320031003200300038000700080060bbda0f486dd90100000000")
	log.Printf("securityBuffer lenght: %v", len(securityBuffer))
	responseHdr := SessionSetupResponse(make([]byte, 8+len(securityBuffer)))
	responseHdr.SetStructureSize()
	responseHdr.SetSecurityBufferOffset(0x48)
	responseHdr.SetSecurityBufferLength(uint16(len(securityBuffer)))
	responseHdr.SetBuffer(securityBuffer)
	// responseHdr.SetSecurityMode(Securi)

	smb2Header := PacketCodec(make([]byte, 64, 64))
	smb2Header.SetProtocolId()
	smb2Header.SetStructureSize()
	smb2Header.SetCreditCharge(1)
	smb2Header.SetCommand(SMB2_SESSION_SETUP)
	smb2Header.SetStatus(STATUS_MORE_PROCESSING_REQUIRED)
	smb2Header.SetCreditRequestResponse(1)
	smb2Header.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	smb2Header.SetNextCommand(0)
	smb2Header.SetMessageId(p.MessageId())
	smb2Header.SetTreeId(0)
	// if sessionID == 0 {
	// 	sessionID = 0xebc20a15
	// } else {
	// 	sessionID++
	// }
	smb2Header.SetSessionId(p.SessionId())
	smb2Header.SetSignature([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	l := len(smb2Header) + len(responseHdr)
	log.Printf("smb2 length: %v, resp len: %v\n", len(smb2Header), len(responseHdr))
	netBIOSHeader := []byte{0x00, 0x00, 0x00, 0x00}
	netBIOSHeader[3] = byte(l)
	netBIOSHeader[2] = byte(l >> 8)

	// smb2Header := []byte{0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	pkt = append(pkt, netBIOSHeader...)
	pkt = append(pkt, smb2Header...)
	pkt = append(pkt, responseHdr...)

	fmt.Printf("handleSessionSetup: %v\n", hex.EncodeToString(pkt))
	c.rwc.Write(pkt)
	fmt.Printf("send response: %d\n", len(pkt))

	return nil
}

func (c *conn) handleSessionSetupNtmlsspAuth(p PacketCodec, msg SessionSetupRequest, ntlpPayload auth.NTLMNegotiateMessage) error {

	pkt := []byte{}
	responseHdr := SessionSetupResponse(make([]byte, 8))
	responseHdr.SetStructureSize()
	responseHdr.SetSecurityBufferOffset(0)
	responseHdr.SetSecurityBufferLength(0)
	// responseHdr.SetSecurityMode(Securi)

	smb2Header := PacketCodec(make([]byte, 64))
	smb2Header.SetProtocolId()
	smb2Header.SetStructureSize()
	smb2Header.SetCreditCharge(1)
	smb2Header.SetCommand(SMB2_SESSION_SETUP)
	smb2Header.SetStatus(STATUS_LOGON_FAILURE)
	smb2Header.SetCreditRequestResponse(1)
	smb2Header.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	smb2Header.SetNextCommand(0)
	smb2Header.SetMessageId(p.MessageId())
	smb2Header.SetTreeId(0)
	// if sessionID == 0 {
	// 	sessionID = 0xebc20a15
	// } else {
	// 	sessionID++
	// }
	smb2Header.SetSessionId(p.SessionId())
	smb2Header.SetSignature([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	l := len(smb2Header) + len(responseHdr)
	log.Printf("smb2 length: %v, resp len: %v\n", len(smb2Header), len(responseHdr))
	netBIOSHeader := []byte{0x00, 0x00, 0x00, 0x00}
	netBIOSHeader[3] = byte(l)
	netBIOSHeader[2] = byte(l >> 8)

	// smb2Header := []byte{0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	pkt = append(pkt, netBIOSHeader...)
	pkt = append(pkt, smb2Header...)
	pkt = append(pkt, responseHdr...)

	fmt.Printf("handleSessionSetup: %v\n", hex.EncodeToString(pkt))
	c.rwc.Write(pkt)
	fmt.Printf("send response: %d\n", len(pkt))

	return nil
}
