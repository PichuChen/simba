package simba

type Dialect uint16

const (
	// MS-SMB2 - v20211006 page 46/481
	SMB2_DIALECT_202 Dialect = 0x0202
	SMB2_DIALECT_21  Dialect = 0x0210
	SMB2_DIALECT_30  Dialect = 0x0300
	SMB2_DIALECT_302 Dialect = 0x0302
	SMB2_DIALECT_311 Dialect = 0x0311

	SMB2_DIALECT_2xx Dialect = 0x02FF
)

func (d Dialect) String() string {
	switch d {
	case SMB2_DIALECT_202:
		return "SMB2_DIALECT_202"
	case SMB2_DIALECT_21:
		return "SMB2_DIALECT_21"
	case SMB2_DIALECT_30:
		return "SMB2_DIALECT_30"
	case SMB2_DIALECT_302:
		return "SMB2_DIALECT_302"
	case SMB2_DIALECT_311:
		return "SMB2_DIALECT_311"
	case SMB2_DIALECT_2xx:
		return "SMB2_DIALECT_2xx"
	}
	return "Unknown"
}
