package linker

const (
	ChunkKindHeader = iota
	ChunkKindOutputSection
	ChunkKindSynthetic
)

type Chunker interface {
	Kind() int
	GetShdr() *Shdr
	GetName() string
	GetShndx() int64
	GetExtraAddrAlign() int64
	UpdateShdr(ctx *Context)
	SetShndx(a int64)
	SetExtraAddrAlign(a int64)
	CopyBuf(ctx *Context)
}

type Chunk struct {
	Name           string
	Shdr           Shdr
	Shndx          int64
	ExtraAddrAlign int64
}

func NewChunk() Chunk {
	return Chunk{Shdr: Shdr{AddrAlign: 1}}
}

func (c *Chunk) Kind() int {
	return ChunkKindSynthetic
}

func (c *Chunk) GetShdr() *Shdr {
	return &c.Shdr
}

func (c *Chunk) GetName() string {
	return c.Name
}

func (c *Chunk) GetShndx() int64 {
	return c.Shndx
}

func (c *Chunk) GetExtraAddrAlign() int64 {
	return c.ExtraAddrAlign
}

func (c *Chunk) UpdateShdr(ctx *Context) {}

func (c *Chunk) SetShndx(a int64) {
	c.Shndx = a
}

func (c *Chunk) SetExtraAddrAlign(a int64) {
	c.ExtraAddrAlign = a
}

func (c *Chunk) CopyBuf(ctx *Context) {}
