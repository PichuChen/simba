package simba

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

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
			c.handleNegotiate(r.SessionId(), msg)
		case SMB2_SESSION_SETUP:
			fmt.Printf("SMB2_SESSION_SETUP\n")
			// msg := SessionSetupRequest(r[64:])
			// c.handleSessionSetup(r.SessionId(), msg)

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
	stringProtocolLength := (uint16(buf[1]) << 16) + (uint16(buf[2]) << 8) + uint16(buf[3])
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

func (c *conn) handleNegotiate(sessionID uint64, msg NegotiateRequest) error {
	fmt.Printf("handleNegotiate: %v\n", msg.ClientGuid())
	pkt := []byte{}
	responseHdr := NegotiateResponse(make([]byte, 64, 64))
	responseHdr.SetStructureSize(65)
	responseHdr.SetSecurityMode(1)
	// responseHdr.SetStatus(0)
	// responseHdr.SetCommand(SMB2_NEGOTIATE)
	// responseHdr.SetCreditRequest(1)

	responseHdr.SetDialectRevision(0x311)
	// responseHdr.SetServerGuid()
	// responseHdr.SetCapabilities(0x1)
	responseHdr.SetMaxTransactSize(0x100000)
	responseHdr.SetMaxReadSize(0x100000)
	responseHdr.SetMaxWriteSize(0x100000)
	responseHdr.SetSystemTime(time.Now())
	// responseHdr.SetServerStartTime(time.Now())
	responseHdr.SetSecurityBufferOffset(128)
	responseHdr.SetSecurityBufferLength(65)

	responseBody := NegotiateResponse(make([]byte, 65, 65))
	responseBody.SetSecurityBufferOffset(128)
	responseBody.SetSecurityBufferLength(65)
	// responseBody.SetGuid(msg.ClientGuid())
	responseBody.SetCapabilities(0x1)
	responseBody.SetMaxTransactSize(0x100000)
	responseBody.SetMaxReadSize(0x100000)
	responseBody.SetMaxWriteSize(0x100000)
	// responseBody.SetSystemTime(0x0)
	// responseBody.SetServerStartTime(0x0)
	// responseBody.SetSecurityBuffer([]byte("NTLMSSP\x00"))
	smb2Header := PacketCodec(make([]byte, 64, 64))
	smb2Header.SetProtocolId()
	smb2Header.SetStructureSize()
	smb2Header.SetCreditCharge(1)
	smb2Header.SetCommand(SMB2_NEGOTIATE)
	smb2Header.SetStatus(0)
	smb2Header.SetCreditRequestResponse(1)
	smb2Header.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	smb2Header.SetNextCommand(0)
	smb2Header.SetMessageId(0)
	smb2Header.SetTreeId(0)
	smb2Header.SetSessionId(sessionID)
	smb2Header.SetSignature([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	l := len(smb2Header) + len(responseHdr) + len(responseBody)
	netBIOSHeader := []byte{0x00, 0x00, 0x00, 0x00}
	netBIOSHeader[3] = byte(l)
	netBIOSHeader[2] = byte(l >> 8)

	// smb2Header := []byte{0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	pkt = append(pkt, netBIOSHeader...)
	pkt = append(pkt, smb2Header...)
	pkt = append(pkt, responseHdr...)
	pkt = append(pkt, responseBody...)

	fmt.Printf("handleNegotiate: %v\n", hex.EncodeToString(pkt))
	c.rwc.Write(pkt)
	fmt.Printf("send response: %d\n", len(pkt))

	return nil

}
