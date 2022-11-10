package simba

type Command uint16

const (
	// MS-SMB2 - v20211006 page 33/481
	SMB2_NEGOTIATE       Command = 0x0000
	SMB2_SESSION_SETUP   Command = 0x0001
	SMB2_LOGOFF          Command = 0x0002
	SMB2_TREE_CONNECT    Command = 0x0003
	SMB2_TREE_DISCONNECT Command = 0x0004
	SMB2_CREATE          Command = 0x0005
	SMB2_CLOSE           Command = 0x0006
	SMB2_FLUSH           Command = 0x0007
	SMB2_READ            Command = 0x0008
	SMB2_WRITE           Command = 0x0009
	SMB2_LOCK            Command = 0x000A
	SMB2_IOCTL           Command = 0x000B
	SMB2_CANCEL          Command = 0x000C
	SMB2_ECHO            Command = 0x000D
	SMB2_QUERY_DIRECTORY Command = 0x000E
	SMB2_CHANGE_NOTIFY   Command = 0x000F
	SMB2_QUERY_INFO      Command = 0x0010
	SMB2_SET_INFO        Command = 0x0011
	SMB2_OPLOCK_BREAK    Command = 0x0012
)

func (c Command) String() string {
	switch c {
	case SMB2_NEGOTIATE:
		return "SMB2_NEGOTIATE"
	case SMB2_SESSION_SETUP:
		return "SMB2_SESSION_SETUP"
	case SMB2_LOGOFF:
		return "SMB2_LOGOFF"
	case SMB2_TREE_CONNECT:
		return "SMB2_TREE_CONNECT"
	case SMB2_TREE_DISCONNECT:
		return "SMB2_TREE_DISCONNECT"
	case SMB2_CREATE:
		return "SMB2_CREATE"
	case SMB2_CLOSE:
		return "SMB2_CLOSE"
	case SMB2_FLUSH:
		return "SMB2_FLUSH"
	case SMB2_READ:
		return "SMB2_READ"
	case SMB2_WRITE:
		return "SMB2_WRITE"
	case SMB2_LOCK:
		return "SMB2_LOCK"
	case SMB2_IOCTL:
		return "SMB2_IOCTL"
	case SMB2_CANCEL:
		return "SMB2_CANCEL"
	case SMB2_ECHO:
		return "SMB2_ECHO"
	case SMB2_QUERY_DIRECTORY:
		return "SMB2_QUERY_DIRECTORY"
	case SMB2_CHANGE_NOTIFY:
		return "SMB2_CHANGE_NOTIFY"
	case SMB2_QUERY_INFO:
		return "SMB2_QUERY_INFO"
	case SMB2_SET_INFO:
		return "SMB2_SET_INFO"
	case SMB2_OPLOCK_BREAK:
		return "SMB2_OPLOCK_BREAK"
	default:
		return "UNKNOWN"
	}
}
