package linker

import (
	"debug/elf"
	"github.com/ksco/rvld/pkg/utils"
)

type GotSection struct {
	Chunk
	GotSyms   []*Symbol
	GotTpSyms []*Symbol
}

func NewGotSection() *GotSection {
	g := &GotSection{Chunk: NewChunk()}
	g.Name = ".got"
	g.Shdr.Type = uint32(elf.SHT_PROGBITS)
	g.Shdr.Flags = uint64(elf.SHF_ALLOC | elf.SHF_WRITE)
	g.Shdr.AddrAlign = 8
	return g
}

func (g *GotSection) AddGotSymbol(ctx *Context, sym *Symbol) {
	sym.SetGotIdx(ctx, int32(g.Shdr.Size/8))
	g.Shdr.Size += 8
	g.GotSyms = append(g.GotSyms, sym)
}

func (g *GotSection) AddGotTpSymbol(ctx *Context, sym *Symbol) {
	sym.SetGotTpIdx(ctx, int32(g.Shdr.Size/8))
	g.Shdr.Size += 8
	g.GotTpSyms = append(g.GotTpSyms, sym)
}

func (g *GotSection) GetEntries(ctx *Context) []GotEntry {
	entries := make([]GotEntry, 0)
	for _, sym := range g.GotSyms {
		idx := sym.GetGotIdx(ctx)
		entries = append(entries,
			NewGotEntry(int64(idx), sym.GetAddr(ctx), int64(elf.R_RISCV_NONE)))
	}

	for _, sym := range g.GotTpSyms {
		idx := sym.GetGotTpIdx(ctx)
		entries = append(entries,
			NewGotEntry(int64(idx), sym.GetAddr(ctx)-ctx.TpAddr, int64(elf.R_RISCV_NONE)))
	}

	return entries
}

func (g *GotSection) UpdateShdr(ctx *Context) {
	if g.Shdr.Size == 0 {
		g.Shdr.Size = 8
	}
}

func (g *GotSection) CopyBuf(ctx *Context) {
	buf := ctx.Buf[g.Shdr.Offset:]
	for i := uint64(0); i < g.Shdr.Size*8; i++ {
		buf[i] = 0
	}

	for _, ent := range g.GetEntries(ctx) {
		if ent.Type == int64(elf.R_RISCV_NONE) {
			utils.Write[uint64](buf[ent.Idx*8:], ent.Val)
		}

		if ent.IsRel() {
			utils.Fatal("unreachable")
		}
	}
}
