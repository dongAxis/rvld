package linker

import (
	"debug/elf"
	"github.com/ksco/rvld/pkg/utils"
	"sort"
)

type MergedSection struct {
	Chunk
	Map map[string]*SectionFragment
}

func NewMergedSection(name string, flags uint64, typ uint32) *MergedSection {
	r := &MergedSection{
		Chunk: NewChunk(),
		Map:   make(map[string]*SectionFragment),
	}
	r.Name = name
	r.Shdr.Flags = flags
	r.Shdr.Type = typ
	return r
}

func GetMergedSectionInstance(ctx *Context, name string, typ uint32, flags uint64) *MergedSection {
	name = GetOutputName(name, flags)
	flags = flags & ^uint64(elf.SHF_GROUP) & ^uint64(elf.SHF_MERGE) &
		^uint64(elf.SHF_STRINGS) & ^uint64(elf.SHF_COMPRESSED)

	find := func() *MergedSection {
		for _, osec := range ctx.MergedSections {
			if name == osec.Name && flags == osec.Shdr.Flags && typ == osec.Shdr.Type {
				return osec
			}
		}
		return nil
	}

	if osec := find(); osec != nil {
		return osec
	}

	osec := NewMergedSection(name, flags, typ)
	ctx.MergedSections = append(ctx.MergedSections, osec)
	return osec
}

func (m *MergedSection) Insert(key string, p2align uint32) *SectionFragment {
	fragment, ok := m.Map[key]
	if !ok {
		fragment = NewSectionFragment(m)
		m.Map[key] = fragment
	}
	if fragment.P2Align < p2align {
		fragment.P2Align = p2align
	}
	return fragment
}

func (m *MergedSection) AssignOffsets() {
	var fragments []struct {
		Key string
		Val *SectionFragment
	}

	for key := range m.Map {
		fragments = append(fragments, struct {
			Key string
			Val *SectionFragment
		}{key, m.Map[key]})
	}

	sort.SliceStable(fragments, func(i, j int) bool {
		x := fragments[i]
		y := fragments[j]
		if x.Val.P2Align != y.Val.P2Align {
			return x.Val.P2Align < y.Val.P2Align
		}
		if len(x.Key) != len(y.Key) {
			return len(x.Key) < len(y.Key)
		}
		return x.Key < y.Key
	})

	offset := uint64(0)
	p2align := uint64(0)
	for _, frag := range fragments {
		if !frag.Val.IsAlive {
			continue
		}

		offset = utils.AlignTo(offset, 1<<frag.Val.P2Align)
		frag.Val.Offset = uint32(offset)
		offset += uint64(len(frag.Key))
		if p2align < uint64(frag.Val.P2Align) {
			p2align = uint64(frag.Val.P2Align)
		}
	}

	m.Shdr.Size = utils.AlignTo(offset, 1<<p2align)
	m.Shdr.AddrAlign = 1 << p2align
}

func (m *MergedSection) CopyBuf(ctx *Context) {
	buf := ctx.Buf[m.Shdr.Offset:]
	for key := range m.Map {
		if frag, ok := m.Map[key]; ok && frag.IsAlive {
			copy(buf[frag.Offset:], key)
		}
	}
}
