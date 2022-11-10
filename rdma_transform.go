package simba

type RDMATransform uint16

const (
	// MS-SMB2 - v20211006 page 50/481
	SMB2_RDMA_TRANSFORM_NONE       RDMATransform = 0x0000
	SMB2_RDMA_TRANSFORM_ENCRYPTION RDMATransform = 0x0001
	SMB2_RDMA_TRANSFORM_SIGNING    RDMATransform = 0x0002
)

type RDMATransformCapability []byte

func (c RDMATransformCapability) TransformCount() uint16 {
	return uint16(le.Uint16(c[0:2]))
}

func (c RDMATransformCapability) SetTransformCount(v uint16) {
	le.PutUint16(c[0:2], v)
}

func (c RDMATransformCapability) RDMATransforms() []RDMATransform {
	var res = make([]RDMATransform, c.TransformCount())
	for i := 0; i < int(c.TransformCount()); i++ {
		res[i] = RDMATransform(le.Uint16(c[8+i*2 : 8+i*2]))
	}
	return res
}

func (c RDMATransformCapability) SetRDMATransforms(v []RDMATransform) {
	c.SetTransformCount(uint16(len(v)))
	for i, t := range v {
		le.PutUint16(c[8+i*2:8+i*2], uint16(t))
	}
}
