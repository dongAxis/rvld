package linker

import (
	"debug/elf"
)

type OutputSection struct {
	Chunk
	Members []*InputSection
	Idx     uint32
}

func NewOutputSection(name string, typ uint32, flags uint64, idx uint32) *OutputSection {
	o := &OutputSection{Chunk: NewChunk()}
	o.Name = name
	o.Shdr.Type = typ
	o.Shdr.Flags = flags
	o.Idx = idx
	return o
}

func GetOutputSectionInstance(
	ctx *Context, name string, typ uint64, flags uint64) *OutputSection {
	name = GetOutputName(name, flags)
	typ = CanonicalizeType(name, typ)
	flags = flags & ^uint64(elf.SHF_GROUP) & ^uint64(elf.SHF_COMPRESSED) &
		^uint64(elf.SHF_LINK_ORDER)

	if typ == uint64(elf.SHT_INIT_ARRAY) || typ == uint64(elf.SHT_FINI_ARRAY) {
		flags |= uint64(elf.SHF_WRITE)
	}

	find := func() *OutputSection {
		for _, os := range ctx.OutputSections {
			if name == os.Name && typ == uint64(os.Shdr.Type) &&
				flags == uint64(os.Shdr.Flags) {
				return os
			}
		}
		return nil
	}

	if os := find(); os != nil {
		return os
	}

	os := NewOutputSection(
		name, uint32(typ), flags, uint32(len(ctx.OutputSections)))
	ctx.OutputSections = append(ctx.OutputSections, os)
	return os
}

func (o *OutputSection) Kind() int {
	return ChunkKindOutputSection
}

func (o *OutputSection) CopyBuf(ctx *Context) {
	if o.Shdr.Type == uint32(elf.SHT_NOBITS) {
		return
	}

	buf := ctx.Buf[o.Shdr.Offset:]
	for i := 0; i < len(o.Members); i++ {
		isec := o.Members[i]
		isec.WriteTo(ctx, buf[isec.Offset:])

		thisEnd := uint64(isec.Offset + isec.ShSize)
		nextStart := o.Shdr.Size
		if i < len(o.Members)-1 {
			nextStart = uint64(o.Members[i+1].Offset)
		}

		for j := thisEnd; j < nextStart; j++ {
			buf[j] = 0
		}
	}
}
