package linker

import (
	"debug/elf"
	"github.com/ksco/rvld/pkg/utils"
	"math"
	"sort"
	"strings"
)

func CreateInternalFile(ctx *Context) {
	obj := &ObjectFile{}
	ctx.InternalObj = obj
	ctx.Objs = append(ctx.Objs, obj)

	ctx.InternalEsyms = make([]Sym, 1)
	obj.Symbols = append(obj.Symbols, NewSymbol(""))
	obj.FirstGlobal = 1
	obj.IsAlive = true
	obj.Priority = 1

	obj.ElfSyms = ctx.InternalEsyms
}

func ResolveSymbols(ctx *Context) {
	for _, file := range ctx.Objs {
		file.ResolveSymbols(ctx)
	}

	MarkLiveObjects(ctx)

	for _, file := range ctx.Objs {
		if !file.IsAlive {
			file.ClearSymbols()
		}
	}

	for _, file := range ctx.Objs {
		if file.IsAlive {
			file.ResolveSymbols(ctx)
		}
	}

	ctx.Objs = utils.RemoveIf[*ObjectFile](ctx.Objs, func(file *ObjectFile) bool {
		return !file.IsAlive
	})
}

func MarkLiveObjects(ctx *Context) {
	roots := make([]*ObjectFile, 0)
	for _, file := range ctx.Objs {
		if file.IsAlive {
			roots = append(roots, file)
		}
	}

	utils.Assert(len(roots) > 0)

	for len(roots) > 0 {
		file := roots[0]
		if !file.IsAlive {
			continue
		}
		file.MarkLiveObjects(ctx, func(o *ObjectFile) {
			roots = append(roots, o)
		})

		roots = roots[1:]
	}
}

func RegisterSectionPieces(ctx *Context) {
	for _, file := range ctx.Objs {
		file.RegisterSectionPieces()
	}
}

func ComputeImportExport(ctx *Context) {
	for _, file := range ctx.Objs {
		file.ComputeImportExport()
	}
}

func ComputeMergedSectionSizes(ctx *Context) {
	for _, file := range ctx.Objs {
		for _, m := range file.MergeableSections {
			if m == nil {
				continue
			}
			for _, frag := range m.Fragments {
				frag.IsAlive = true
			}
		}
	}

	for _, sec := range ctx.MergedSections {
		sec.AssignOffsets()
	}
}

func CreateSyntheticSections(ctx *Context) {
	push := func(chunk Chunker) Chunker {
		ctx.Chunks = append(ctx.Chunks, chunk)
		return chunk
	}

	ctx.Ehdr = push(NewOutputEhdr()).(*OutputEhdr)
	ctx.Phdr = push(NewOutputPhdr()).(*OutputPhdr)
	ctx.Shdr = push(NewOutputShdr()).(*OutputShdr)

	ctx.Got = push(NewGotSection()).(*GotSection)
}

func BinSections(ctx *Context) {
	group := make([][]*InputSection, len(ctx.OutputSections))
	for _, file := range ctx.Objs {
		for _, isec := range file.Sections {
			if isec == nil || !isec.IsAlive {
				continue
			}

			idx := isec.OutputSection.Idx
			group[idx] = append(group[idx], isec)
		}
	}

	for i, osec := range ctx.OutputSections {
		osec.Members = group[i]
	}
}

func CollectOutputSections(ctx *Context) []Chunker {
	osecs := make([]Chunker, 0)
	for _, osec := range ctx.OutputSections {
		if len(osec.Members) != 0 {
			osecs = append(osecs, osec)
		}
	}
	for _, osec := range ctx.MergedSections {
		if osec.Shdr.Size > 0 {
			osecs = append(osecs, osec)
		}
	}

	sort.SliceStable(osecs, func(i, j int) bool {
		return osecs[i].GetName() < osecs[j].GetName()
	})
	return osecs
}

func AddSyntheticSymbols(ctx *Context) {
	obj := ctx.InternalObj

	add := func(name string) *Symbol {
		esym := Sym{
			Info:  uint8(elf.STT_NOTYPE)<<4 | uint8(elf.STB_GLOBAL)&0xf,
			Shndx: uint16(elf.SHN_ABS),
			Other: uint8(elf.STV_HIDDEN) << 6,
		}
		ctx.InternalEsyms = append(ctx.InternalEsyms, esym)
		sym := GetSymbolByName(ctx, name)
		sym.Value = 0xdeadbeef
		obj.Symbols = append(obj.Symbols, sym)
		return sym
	}

	ctx.__InitArrayStart = add("__init_array_start")
	ctx.__InitArrayEnd = add("__init_array_end")
	ctx.__FiniArrayStart = add("__fini_array_start")
	ctx.__FiniArrayEnd = add("__fini_array_end")
	ctx.__PreinitArrayStart = add("__preinit_array_start")
	ctx.__PreinitArrayEnd = add("__preinit_array_end")

	ctx.__GlobalPointer = add("__global_pointer$")

	obj.ElfSyms = ctx.InternalEsyms

	obj.ResolveSymbols(ctx)
}

func ClaimUnresolvedSymbols(ctx *Context) {
	for _, file := range ctx.Objs {
		file.ClaimUnresolvedSymbols(ctx)
	}
}

func ScanRels(ctx *Context) {
	for _, file := range ctx.Objs {
		file.ScanRelocations(ctx)
	}

	syms := make([]*Symbol, 0)
	for _, file := range ctx.Objs {
		for _, sym := range file.Symbols {
			if sym.File == file {
				if sym.Flags != 0 || sym.IsExported {
					syms = append(syms, sym)
				}
			}
		}
	}

	ctx.SymbolsAux = make([]SymbolAux, 0, len(syms))

	addAux := func(sym *Symbol) {
		if sym.AuxIdx == -1 {
			size := int32(len(ctx.SymbolsAux))
			sym.AuxIdx = size
			ctx.SymbolsAux = append(ctx.SymbolsAux, NewSymbolAux())
		}
	}

	for _, sym := range syms {
		addAux(sym)

		if sym.Flags&NEEDS_GOT != 0 {
			ctx.Got.AddGotSymbol(ctx, sym)
		}

		if sym.Flags&NEEDS_GOTTP != 0 {
			ctx.Got.AddGotTpSymbol(ctx, sym)
		}

		sym.Flags = 0
	}
}

func ComputeSectionSizes(ctx *Context) {
	for _, osec := range ctx.OutputSections {
		offset := uint64(0)
		p2align := int64(0)

		for _, isec := range osec.Members {
			offset = utils.AlignTo(offset, 1<<isec.P2Align)
			isec.Offset = uint32(offset)
			offset += uint64(isec.ShSize)
			p2align = int64(math.Max(float64(p2align), float64(isec.P2Align)))
		}

		osec.Shdr.Size = offset
		osec.Shdr.AddrAlign = 1 << p2align
	}
}

func SortOutputSections(ctx *Context) {
	getRank1 := func(chunk Chunker) int32 {
		typ := chunk.GetShdr().Type
		flags := chunk.GetShdr().Flags

		if flags&uint64(elf.SHF_ALLOC) == 0 {
			return math.MaxInt32 - 1
		}
		if chunk == ctx.Shdr {
			return math.MaxInt32
		}

		if chunk == ctx.Ehdr {
			return 0
		}
		if chunk == ctx.Phdr {
			return 1
		}
		if typ == uint32(elf.SHT_NOTE) {
			return 3
		}

		b2i := func(b bool) int {
			if b {
				return 1
			}
			return 0
		}

		writeable := b2i(flags&uint64(elf.SHF_WRITE) != 0)
		notExec := b2i(flags&uint64(elf.SHF_EXECINSTR) == 0)
		notTls := b2i(flags&uint64(elf.SHF_TLS) == 0)
		notRelro := b2i(!isRelro(ctx, chunk))
		isBss := b2i(typ == uint32(elf.SHT_NOBITS))

		return int32((1 << 10) | writeable<<9 | notExec<<8 | notTls<<7 | notRelro<<6 | isBss<<5)
	}
	getRank2 := func(chunk Chunker) int32 {
		if chunk.GetShdr().Type == uint32(elf.SHT_NOTE) {
			return -int32(chunk.GetShdr().AddrAlign)
		}

		if chunk.GetName() == ".toc" {
			return 2
		}
		if chunk == ctx.Got {
			return 1
		}
		return 0
	}

	sort.SliceStable(ctx.Chunks, func(i, j int) bool {
		x := getRank1(ctx.Chunks[i])
		y := getRank1(ctx.Chunks[j])
		if x != y {
			return x < y
		}

		return getRank2(ctx.Chunks[i]) < getRank2(ctx.Chunks[j])
	})
}

func doSetOsecOffsets(ctx *Context) uint64 {
	alignment := func(chunk Chunker) uint64 {
		return uint64(math.Max(float64(chunk.GetExtraAddrAlign()),
			float64(chunk.GetShdr().AddrAlign)))
	}

	addr := ImageBase
	for _, chunk := range ctx.Chunks {
		if chunk.GetShdr().Flags&uint64(elf.SHF_ALLOC) == 0 {
			continue
		}

		if isTbss(chunk) {
			chunk.GetShdr().Addr = addr
			continue
		}

		addr = utils.AlignTo(addr, alignment(chunk))
		chunk.GetShdr().Addr = addr

		addr += chunk.GetShdr().Size
	}

	for i := 0; i < len(ctx.Chunks); {
		if isTbss(ctx.Chunks[i]) {
			addr := ctx.Chunks[i].GetShdr().Addr
			for ; i < len(ctx.Chunks) && isTbss(ctx.Chunks[i]); i++ {
				addr = utils.AlignTo(addr, alignment(ctx.Chunks[i]))
				ctx.Chunks[i].GetShdr().Addr = addr
				addr += ctx.Chunks[i].GetShdr().Size
			}
		} else {
			i++
		}
	}

	fileoff := uint64(0)
	i := 0
	for i < len(ctx.Chunks) && ctx.Chunks[i].GetShdr().Flags&uint64(elf.SHF_ALLOC) != 0 {
		first := ctx.Chunks[i]
		utils.Assert(first.GetShdr().Type != uint32(elf.SHT_NOBITS))

		fileoff = utils.AlignTo(fileoff, alignment(first))

		for {
			ctx.Chunks[i].GetShdr().Offset = fileoff + ctx.Chunks[i].GetShdr().Addr - first.GetShdr().Addr
			i++

			if i >= len(ctx.Chunks) ||
				ctx.Chunks[i].GetShdr().Flags&uint64(elf.SHF_ALLOC) == 0 ||
				ctx.Chunks[i].GetShdr().Type == uint32(elf.SHT_NOBITS) {
				break
			}

			if ctx.Chunks[i].GetShdr().Addr < first.GetShdr().Addr {
				break
			}

			gapSize := ctx.Chunks[i].GetShdr().Addr - ctx.Chunks[i-1].GetShdr().Addr - ctx.Chunks[i-1].GetShdr().Size

			if gapSize >= PageSize {
				break
			}
		}

		fileoff = ctx.Chunks[i-1].GetShdr().Offset + ctx.Chunks[i-1].GetShdr().Size

		for i < len(ctx.Chunks) &&
			ctx.Chunks[i].GetShdr().Flags&uint64(elf.SHF_ALLOC) != 0 &&
			ctx.Chunks[i].GetShdr().Type == uint32(elf.SHT_NOBITS) {
			i++
		}
	}

	for ; i < len(ctx.Chunks); i++ {
		fileoff = utils.AlignTo(fileoff, ctx.Chunks[i].GetShdr().AddrAlign)
		ctx.Chunks[i].GetShdr().Offset = fileoff
		fileoff += ctx.Chunks[i].GetShdr().Size
	}
	return fileoff
}

func SetOsecOffsets(ctx *Context) uint64 {
	for {
		fileoff := doSetOsecOffsets(ctx)

		if ctx.Phdr == nil {
			return fileoff
		}

		size := ctx.Phdr.Shdr.Size
		ctx.Phdr.UpdateShdr(ctx)

		if size == ctx.Phdr.Shdr.Size {
			return fileoff
		}
	}
}

func shrinkSection(isec *InputSection) {
	rels := isec.GetRels()
	isec.Deltas = make([]int32, len(rels)+1)

	delta := int32(0)
	times := 0
	for i := 0; i < len(rels); i++ {
		r := rels[i]
		isec.Deltas[i] = delta

		if r.Type == uint32(elf.R_RISCV_ALIGN) {
			times++
			loc := isec.GetAddr() + r.Offset - uint64(delta)
			nextLoc := loc + uint64(r.Addend)
			alignment := utils.BitCeil(uint64(r.Addend + 1))
			delta += int32(nextLoc - utils.AlignTo(loc, alignment))
		}
	}

	isec.Deltas[len(rels)] = delta
	isec.ShSize -= uint32(delta)
}

func ResizeSections(ctx *Context) uint64 {
	isResizeable := func(isec *InputSection) bool {
		return isec != nil && isec.IsAlive &&
			isec.Shdr().Flags&uint64(elf.SHF_ALLOC) != 0 &&
			isec.Shdr().Flags&uint64(elf.SHF_EXECINSTR) != 0
	}
	for _, file := range ctx.Objs {
		for _, isec := range file.Sections {
			if isResizeable(isec) {
				shrinkSection(isec)
			}
		}
	}

	for _, file := range ctx.Objs {
		for _, sym := range file.Symbols {
			if sym.File != file {
				continue
			}

			isec := sym.InputSection
			if isec == nil || len(isec.Deltas) == 0 {
				continue
			}

			rels := isec.GetRels()
			idx := sort.Search(len(rels), func(i int) bool {
				return rels[i].Offset >= sym.Value
			})

			sym.Value -= uint64(isec.Deltas[idx])
		}
	}

	ComputeSectionSizes(ctx)
	return SetOsecOffsets(ctx)
}

func FixSyntheticSymbols(ctx *Context) {
	start := func(sym *Symbol, chunk Chunker) {
		if sym != nil && chunk != nil {
			sym.SetOutputSection(chunk)
			sym.Value = chunk.GetShdr().Addr
		}
	}

	stop := func(sym *Symbol, chunk Chunker) {
		if sym != nil && chunk != nil {
			sym.SetOutputSection(chunk)
			sym.Value = chunk.GetShdr().Addr + chunk.GetShdr().Size
		}
	}

	outputSections := make([]Chunker, 0)
	for _, chunk := range ctx.Chunks {
		if chunk.Kind() != ChunkKindHeader {
			outputSections = append(outputSections, chunk)
		}
	}

	for _, chunk := range outputSections {
		switch chunk.GetShdr().Type {
		case uint32(elf.SHT_INIT_ARRAY):
			start(ctx.__InitArrayStart, chunk)
			stop(ctx.__InitArrayEnd, chunk)
		case uint32(elf.SHT_PREINIT_ARRAY):
			start(ctx.__PreinitArrayStart, chunk)
			stop(ctx.__PreinitArrayEnd, chunk)
		case uint32(elf.SHT_FINI_ARRAY):
			start(ctx.__FiniArrayStart, chunk)
			stop(ctx.__FiniArrayEnd, chunk)
		}
	}

	ctx.__GlobalPointer.SetOutputSection(outputSections[0])
	ctx.__GlobalPointer.Value = 0
}

func isRelro(ctx *Context, chunk Chunker) bool {
	flags := chunk.GetShdr().Flags
	typ := chunk.GetShdr().Type

	if flags&uint64(elf.SHF_WRITE) != 0 {
		return (flags&uint64(elf.SHF_TLS) != 0) || typ == uint32(elf.SHT_INIT_ARRAY) ||
			typ == uint32(elf.SHT_FINI_ARRAY) || typ == uint32(elf.SHT_PREINIT_ARRAY) ||
			chunk == ctx.Got || chunk.GetName() == ".toc" ||
			strings.HasSuffix(chunk.GetName(), "rel.ro")
	}
	return false
}

func isTbss(chunk Chunker) bool {
	return chunk.GetShdr().Type == uint32(elf.SHT_NOBITS) && chunk.GetShdr().Flags&uint64(elf.SHF_TLS) != 0
}
