package linker

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"github.com/ksco/rvld/pkg/utils"
	"unsafe"
)

type OutputEhdr struct {
	Chunk
}

func NewOutputEhdr() *OutputEhdr {
	return &OutputEhdr{
		Chunk: Chunk{
			Shdr: Shdr{
				Flags:     uint64(elf.SHF_ALLOC),
				Size:      uint64(unsafe.Sizeof(Ehdr{})),
				AddrAlign: 8,
			},
		},
	}
}

func (o *OutputEhdr) Kind() int {
	return ChunkKindHeader
}

func GetEntryAddr(ctx *Context) uint64 {
	for _, osec := range ctx.OutputSections {
		if osec.Name == ".text" {
			return osec.Shdr.Addr
		}
	}
	return 0
}

func GetFlags(ctx *Context) uint32 {
	objs := make([]*ObjectFile, len(ctx.Objs))
	copy(objs, ctx.Objs)

	objs = utils.RemoveIf[*ObjectFile](objs, func(file *ObjectFile) bool {
		return file == ctx.InternalObj
	})

	if len(objs) == 0 {
		return 0
	}

	ret := objs[0].GetEhdr().Flags
	for i := 1; i < len(objs); i++ {
		if objs[i].GetEhdr().Flags&EF_RISCV_RVC != 0 {
			ret |= EF_RISCV_RVC
		}
	}

	return ret
}

func (o *OutputEhdr) CopyBuf(ctx *Context) {
	var err error
	ehdr := &Ehdr{}
	WriteMagic(ehdr.Ident[:])
	ehdr.Ident[elf.EI_CLASS] = uint8(elf.ELFCLASS64)
	ehdr.Ident[elf.EI_DATA] = uint8(elf.ELFDATA2LSB)
	ehdr.Ident[elf.EI_VERSION] = uint8(elf.EV_CURRENT)
	ehdr.Ident[elf.EI_OSABI] = 0
	ehdr.Ident[elf.EI_ABIVERSION] = 0
	ehdr.Type = uint16(elf.ET_EXEC)
	ehdr.Machine = uint16(elf.EM_RISCV)
	ehdr.Version = uint32(elf.EV_CURRENT)
	ehdr.Entry = GetEntryAddr(ctx)
	ehdr.PhOff = ctx.Phdr.Shdr.Offset
	ehdr.ShOff = ctx.Shdr.Shdr.Offset
	ehdr.Flags = GetFlags(ctx)
	ehdr.EhSize = uint16(unsafe.Sizeof(Ehdr{}))
	ehdr.PhEntSize = uint16(unsafe.Sizeof(Phdr{}))
	ehdr.PhNum = uint16(ctx.Phdr.Shdr.Size) / uint16(unsafe.Sizeof(Phdr{}))
	ehdr.ShEntSize = uint16(unsafe.Sizeof(Shdr{}))
	ehdr.ShNum = uint16(ctx.Shdr.Shdr.Size) / uint16(unsafe.Sizeof(Shdr{}))

	buf := &bytes.Buffer{}
	err = binary.Write(buf, binary.LittleEndian, ehdr)
	utils.MustNo(err)
	copy(ctx.Buf[o.Shdr.Offset:], buf.Bytes())
}
