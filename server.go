package simba

import (
	"fmt"
	"net"
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
		w, err := c.readRequest()
		if err != nil {
			fmt.Printf("readRequest error: %v\n", err)
			return
		}
		fmt.Printf("readRequest: %v\n", w)
	}

}

func (c *conn) readRequest() (w *response, err error) {
	var buf [1024]byte
	n, err := c.rwc.Read(buf[:])
	if err != nil {
		return nil, err
	}
	fmt.Printf("readRequest: %v len: %d\n", buf[:n], n)
	// zero := buf[0]
	stringProtocolLength := (buf[1] << 16) + (buf[2] << 8) + buf[3]
	smb2Message := buf[4 : 4+stringProtocolLength]

	msg := PacketCodec(smb2Message)
	fmt.Printf("msg: %+v\n", msg)
	if msg.IsInvalid() {
		fmt.Printf("msg is invalid\n")
		return nil, fmt.Errorf("msg is invalid")
	}

	fmt.Printf("msg type: %v\n", msg.Command())

	return nil, nil

}
