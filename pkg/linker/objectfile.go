package linker

import (
	"bytes"
	"debug/elf"
	"github.com/ksco/rvld/pkg/utils"
	"math"
	"sort"
	"strings"
	"unsafe"
)

type ObjectFile struct {
	InputFile
	Sections          []*InputSection
	MergeableSections []*MergeableSection

	SymtabSec      *Shdr
	SymtabShndxSec []uint32
}

func NewObjectFile(file *File, inLib bool) *ObjectFile {
	o := &ObjectFile{InputFile: *NewInputFile(file)}
	o.IsAlive = !inLib
	return o
}

func (o *ObjectFile) parse(ctx *Context) {
	o.SymtabSec = o.FindSection(uint32(elf.SHT_SYMTAB))
	if o.SymtabSec != nil {
		o.FirstGlobal = int64(o.SymtabSec.Info)

		o.InputFile.FillUpElfSyms(o.SymtabSec)
		o.InputFile.SymbolStrtab = o.InputFile.
			GetBytesFromIdx(int64(o.SymtabSec.Link))
	}

	o.initializeSections(ctx)
	o.initializeSymbols(ctx)
	o.sortRelocations()
	o.initializeMergeableSections(ctx)
	o.skipEhframeSections(ctx)
}

func (o *ObjectFile) initializeSections(ctx *Context) {
	o.Sections = make([]*InputSection, len(o.InputFile.ElfSections))
	for i := 0; i < len(o.ElfSections); i++ {
		shdr := &o.ElfSections[i]
		if (shdr.Flags&uint64(SHF_EXCLUDE) != 0) &&
			(shdr.Flags&uint64(elf.SHF_ALLOC) == 0) &&
			(shdr.Type != SHT_LLVM_ADDRSIG) {
			continue
		}

		switch elf.SectionType(shdr.Type) {
		case elf.SHT_GROUP:
			// Ignore
		case elf.SHT_SYMTAB_SHNDX:
			o.FillUpSymtabShndxSec(shdr)
		case elf.SHT_SYMTAB, elf.SHT_STRTAB, elf.SHT_REL, elf.SHT_RELA,
			elf.SHT_NULL:
			break
		default:
			name := getName(o.InputFile.ShStrtab, shdr.Name)

			if name == ".note.GNU-stack" {
				continue
			}
			if strings.HasPrefix(name, ".gnu.warning.") {
				continue
			}

			o.Sections[i] = NewInputSection(ctx, o, name, int64(i))
		}
	}

	for i := 0; i < len(o.InputFile.ElfSections); i++ {
		shdr := &o.InputFile.ElfSections[i]
		if shdr.Type != uint32(elf.SHT_RELA) {
			continue
		}

		if shdr.Info >= uint32(len(o.Sections)) {
			utils.Fatal("invalid relocated section index")
		}

		if target := o.Sections[shdr.Info]; target != nil {
			utils.Assert(target.RelsecIdx == math.MaxUint32)
			target.RelsecIdx = uint32(i)
		}
	}
}

func (o *ObjectFile) initializeSymbols(ctx *Context) {
	if o.SymtabSec == nil {
		return
	}

	o.LocalSyms = make([]Symbol, o.FirstGlobal)
	for i := 0; i < len(o.LocalSyms); i++ {
		o.LocalSyms[i] = *NewSymbol("")
	}
	o.LocalSyms[0].File = o
	o.LocalSyms[0].SymIdx = 0

	for i := int64(1); i < o.FirstGlobal; i++ {
		esym := &o.ElfSyms[i]
		if esym.IsCommon() {
			utils.Fatal("common local symbol?")
		}

		name := getName(o.SymbolStrtab, esym.Name)
		if name == "" && esym.Type() == uint8(elf.STT_SECTION) {
			if sec := o.GetSection(esym, i); sec != nil {
				name = sec.Name()
			}
		}

		sym := &o.LocalSyms[i]
		sym.Name = name
		sym.File = o
		sym.Value = esym.Val
		sym.SymIdx = int32(i)

		if !esym.IsAbs() {
			sym.SetInputSection(o.Sections[o.GetShndx(esym, i)])
		}
	}

	o.Symbols = make([]*Symbol, len(o.ElfSyms))

	for i := int64(0); i < o.FirstGlobal; i++ {
		o.Symbols[i] = &o.LocalSyms[i]
	}

	for i := o.FirstGlobal; i < int64(len(o.ElfSyms)); i++ {
		esym := &o.ElfSyms[i]
		name := getName(o.SymbolStrtab, esym.Name)
		o.Symbols[i] = GetSymbolByName(ctx, name)
	}
}

func (o *ObjectFile) sortRelocations() {
	for i := 1; i < len(o.Sections); i++ {
		isec := o.Sections[i]
		if isec == nil || !isec.IsAlive || isec.Shdr().Flags&uint64(elf.SHF_ALLOC) == 0 {
			continue
		}

		rels := isec.GetRels()
		sort.SliceStable(rels, func(i, j int) bool {
			return rels[i].Offset < rels[j].Offset
		})
	}
}

func findNull(data []byte, entSize int) int {
	if entSize == 1 {
		return bytes.Index(data, []byte{0})
	}

	for i := 0; i <= len(data)-entSize; i += entSize {
		bs := data[i : i+entSize]
		if utils.AllZeros(bs) {
			return i
		}
	}
	return -1
}

func splitSection(ctx *Context, isec *InputSection) *MergeableSection {
	rec := &MergeableSection{}
	shdr := isec.Shdr()
	rec.Parent = GetMergedSectionInstance(ctx, isec.Name(), shdr.Type, shdr.Flags)
	rec.P2Align = isec.P2Align

	data := isec.Contents
	offset := uint64(0)
	if shdr.Flags&uint64(elf.SHF_STRINGS) != 0 {
		for len(data) > 0 {
			end := findNull(data, int(shdr.EntSize))
			if end == -1 {
				utils.Fatal("string is not null terminated")
			}

			substr := data[:uint64(end)+shdr.EntSize]
			data = data[uint64(end)+shdr.EntSize:]
			rec.Strs = append(rec.Strs, string(substr))
			rec.FragOffsets = append(rec.FragOffsets, uint32(offset))
			offset += uint64(end) + shdr.EntSize
		}
	} else {
		if uint64(len(data))%shdr.EntSize != 0 {
			utils.Fatal("section size is not multiple of entsize")
		}
		for len(data) > 0 {
			substr := data[:shdr.EntSize]
			data = data[shdr.EntSize:]
			rec.Strs = append(rec.Strs, string(substr))
			rec.FragOffsets = append(rec.FragOffsets, uint32(offset))
			offset += shdr.EntSize
		}
	}

	return rec
}

func (o *ObjectFile) initializeMergeableSections(ctx *Context) {
	o.MergeableSections = make([]*MergeableSection, len(o.Sections))
	for i := 0; i < len(o.Sections); i++ {
		isec := o.Sections[i]
		if isec != nil && isec.IsAlive && isec.Shdr().Flags&uint64(elf.SHF_MERGE) != 0 &&
			isec.ShSize > 0 && isec.Shdr().EntSize > 0 &&
			isec.RelsecIdx == math.MaxUint32 {
			o.MergeableSections[i] = splitSection(ctx, isec)
			isec.IsAlive = false
		}
	}
}

func (o *ObjectFile) skipEhframeSections(ctx *Context) {
	for i := 0; i < len(o.Sections); i++ {
		isec := o.Sections[i]
		if isec != nil && isec.IsAlive && isec.Name() == ".eh_frame" {
			isec.IsAlive = false
		}
	}
}

func (o *ObjectFile) FillUpSymtabShndxSec(s *Shdr) {
	bs := o.InputFile.GetBytesFromShdr(s)
	nums := len(bs) / int(unsafe.Sizeof(uint32(1)))
	o.SymtabShndxSec = make([]uint32, 0)
	for nums > 0 {
		o.SymtabShndxSec = append(o.SymtabShndxSec, utils.Read[uint32](bs))
		bs = bs[4:]
		nums--
	}
}

func (o *ObjectFile) GetSection(esym *Sym, idx int64) *InputSection {
	return o.Sections[o.GetShndx(esym, idx)]
}

func (o *ObjectFile) GetShndx(esym *Sym, idx int64) int64 {
	utils.Assert(idx >= 0 && idx < int64(len(o.ElfSyms)))
	if esym.Shndx == uint16(elf.SHN_XINDEX) {
		return int64(o.SymtabShndxSec[idx])
	}
	return int64(esym.Shndx)
}

func (o *ObjectFile) ResolveSymbols(ctx *Context) {
	for i := o.FirstGlobal; i < int64(len(o.ElfSyms)); i++ {
		sym := o.Symbols[i]
		esym := &o.ElfSyms[i]

		if esym.IsUndef() {
			continue
		}

		var isec *InputSection
		if !esym.IsAbs() && !esym.IsCommon() {
			isec = o.GetSection(esym, i)
			if isec == nil {
				continue
			}
		}

		if GetRank(o, esym, !o.IsAlive) < sym.GetRank() {
			sym.File = o
			sym.SetInputSection(isec)
			sym.Value = esym.Val
			sym.SymIdx = int32(i)
			sym.VerIdx = ctx.DefaultVersion
			sym.IsWeak = esym.IsWeak()
			sym.IsExported = false
		}
	}
}

func (o *ObjectFile) MarkLiveObjects(ctx *Context, feeder func(*ObjectFile)) {
	utils.Assert(o.IsAlive)

	for i := o.FirstGlobal; i < int64(len(o.ElfSyms)); i++ {
		esym := &o.ElfSyms[i]
		sym := o.Symbols[i]

		o.MergeVisibility(ctx, sym, esym.StVisibility())

		if esym.IsWeak() {
			continue
		}

		if sym.File == nil {
			continue
		}

		keep := esym.IsUndef() || (esym.IsCommon() && !sym.ElfSym().IsCommon())
		if keep && !sym.File.SwapIsAlive(true) {
			feeder(sym.File)
		}
	}
}

func (o *ObjectFile) MergeVisibility(ctx *Context, sym *Symbol, visibility uint8) {
	if visibility == uint8(elf.STV_INTERNAL) {
		visibility = uint8(elf.STV_HIDDEN)
	}

	priority := func(visibility uint8) int {
		switch visibility {
		case uint8(elf.STV_HIDDEN):
			return 1
		case uint8(elf.STV_PROTECTED):
			return 2
		case uint8(elf.STV_DEFAULT):
			return 3
		}
		utils.Fatal("unknown symbol visibility")
		return 0
	}

	if priority(sym.Visibility) > priority(visibility) {
		sym.Visibility = visibility
	}
}

func (o *ObjectFile) ClearSymbols() {
	for _, sym := range o.GetGlobalSyms() {
		if sym.File == o {
			sym.Clear()
		}
	}
}

func (o *ObjectFile) RegisterSectionPieces() {
	for _, m := range o.MergeableSections {
		if m == nil {
			continue
		}
		m.Fragments = make([]*SectionFragment, 0, len(m.Strs))
		for i := 0; i < len(m.Strs); i++ {
			m.Fragments = append(m.Fragments, m.Parent.Insert(m.Strs[i], uint32(m.P2Align)))
		}
	}

	for i := int64(1); i < int64(len(o.ElfSyms)); i++ {
		sym := o.Symbols[i]
		esym := &o.ElfSyms[i]

		if esym.IsAbs() || esym.IsCommon() || esym.IsUndef() {
			continue
		}

		m := o.MergeableSections[o.GetShndx(esym, i)]
		if m == nil {
			continue
		}

		frag, fragOffset := m.GetFragment(uint32(esym.Val))
		if frag == nil {
			utils.Fatal("bad symbol value")
		}
		sym.SetSectionFragment(frag)
		sym.Value = uint64(fragOffset)
	}

	nFragSyms := 0
	for _, isec := range o.Sections {
		if isec == nil || !isec.IsAlive || isec.Shdr().Flags&uint64(elf.SHF_ALLOC) == 0 {
			continue
		}
		for _, r := range isec.GetRels() {
			if esym := &o.ElfSyms[r.Sym]; esym.Type() == uint8(elf.STT_SECTION) &&
				o.MergeableSections[o.GetShndx(esym, int64(r.Sym))] != nil {
				nFragSyms++
			}
		}
	}

	for i := 0; i < nFragSyms; i++ {
		o.FragSyms = append(o.FragSyms, *NewSymbol(""))
	}

	idx := 0
	for _, isec := range o.Sections {
		if isec == nil || !isec.IsAlive || isec.Shdr().Flags&uint64(elf.SHF_ALLOC) == 0 {
			continue
		}

		for i := 0; i < len(isec.GetRels()); i++ {
			r := &isec.GetRels()[i]
			esym := &o.ElfSyms[r.Sym]
			if esym.Type() != uint8(elf.STT_SECTION) {
				continue
			}

			m := o.MergeableSections[o.GetShndx(esym, int64(r.Sym))]
			if m == nil {
				continue
			}

			frag, fragOffset := m.GetFragment(uint32(esym.Val) + uint32(r.Addend))
			if frag == nil {
				utils.Fatal("bad relocation")
			}

			sym := &o.FragSyms[idx]
			sym.File = o
			sym.Name = "<fragment>"
			sym.SymIdx = int32(r.Sym)
			sym.Visibility = uint8(elf.STV_HIDDEN)
			sym.SetSectionFragment(frag)
			sym.Value = uint64(fragOffset) - uint64(r.Addend)

			r.Sym = uint32(len(o.ElfSyms)) + uint32(idx)
			idx++
		}
	}

	utils.Assert(idx == len(o.FragSyms))

	for i := 0; i < len(o.FragSyms); i++ {
		o.Symbols = append(o.Symbols, &o.FragSyms[i])
	}
}

func (o *ObjectFile) ComputeImportExport() {
	for _, sym := range o.GetGlobalSyms() {
		if sym.File == nil || sym.Visibility == uint8(elf.STV_HIDDEN) ||
			sym.VerIdx == VER_NDX_LOCAL {
			continue
		}

		if sym.File == o {
			sym.IsExported = true
		}
	}
}

func (o *ObjectFile) ClaimUnresolvedSymbols(ctx *Context) {
	if !o.IsAlive {
		return
	}

	for i := o.FirstGlobal; i < int64(len(o.ElfSyms)); i++ {
		esym := &o.ElfSyms[i]
		if !esym.IsUndef() {
			continue
		}

		sym := o.Symbols[i]
		if sym.File != nil && (!sym.ElfSym().IsUndef() || sym.File.Priority <= o.Priority) {
			continue
		}

		if esym.IsUndefWeak() {
			sym.File = o
			sym.InputSection = nil
			sym.OutputSection = nil
			sym.SectionFragment = nil
			sym.Value = 0
			sym.SymIdx = int32(i)
			sym.IsWeak = false
			sym.IsExported = false
			sym.VerIdx = ctx.DefaultVersion
		}
	}
}

func (o *ObjectFile) ScanRelocations(ctx *Context) {
	for _, isec := range o.Sections {
		if isec != nil && isec.IsAlive && isec.Shdr().Flags&uint64(elf.SHF_ALLOC) != 0 {
			isec.ScanRelocations(ctx)
		}
	}
}
