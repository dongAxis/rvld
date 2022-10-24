package linker

import (
	"debug/elf"
)

const (
	NEEDS_GOT   uint32 = 1 << 0
	NEEDS_GOTTP uint32 = 1 << 3
)

type Symbol struct {
	File *ObjectFile

	InputSection    *InputSection
	OutputSection   Chunker
	SectionFragment *SectionFragment

	Value uint64
	Name  string

	SymIdx int32
	AuxIdx int32
	VerIdx uint16

	Flags      uint32
	Visibility uint8

	IsWeak     bool
	IsExported bool
}

func NewSymbol(name string) *Symbol {
	s := &Symbol{
		Name:       name,
		SymIdx:     -1,
		AuxIdx:     -1,
		Visibility: uint8(elf.STV_DEFAULT),
	}
	return s
}

func GetSymbolByName(ctx *Context, name string) *Symbol {
	if sym, ok := ctx.SymbolMap[name]; ok {
		return sym
	}
	ctx.SymbolMap[name] = NewSymbol(name)
	return ctx.SymbolMap[name]
}

func (s *Symbol) SetInputSection(isec *InputSection) {
	s.InputSection = isec
	s.OutputSection = nil
	s.SectionFragment = nil
}
func (s *Symbol) SetOutputSection(osec Chunker) {
	s.InputSection = nil
	s.OutputSection = osec
	s.SectionFragment = nil
}
func (s *Symbol) SetSectionFragment(frag *SectionFragment) {
	s.InputSection = nil
	s.OutputSection = nil
	s.SectionFragment = frag
}

func (s *Symbol) GetGotIdx(ctx *Context) int32 {
	if s.AuxIdx == -1 {
		return -1
	}
	return ctx.SymbolsAux[s.AuxIdx].GotIdx
}

func (s *Symbol) GetGotTpIdx(ctx *Context) int32 {
	if s.AuxIdx == -1 {
		return -1
	}
	return ctx.SymbolsAux[s.AuxIdx].GotTpIdx
}

func (s *Symbol) SetGotIdx(ctx *Context, idx int32) {
	ctx.SymbolsAux[s.AuxIdx].GotIdx = idx
}

func (s *Symbol) SetGotTpIdx(ctx *Context, idx int32) {
	ctx.SymbolsAux[s.AuxIdx].GotTpIdx = idx
}

func (s *Symbol) ElfSym() *Sym {
	return &s.File.ElfSyms[s.SymIdx]
}

func (s *Symbol) GetAddr(ctx *Context) uint64 {
	if s.SectionFragment != nil {
		if !s.SectionFragment.IsAlive {
			return 0
		}
		return s.SectionFragment.GetAddr() + s.Value
	}

	if s.InputSection == nil {
		return s.Value
	}

	if !s.InputSection.IsAlive {
		return 0
	}

	return s.InputSection.GetAddr() + s.Value
}

func (s *Symbol) GetGotTpAddr(ctx *Context) uint64 {
	return ctx.Got.Shdr.Addr + uint64(s.GetGotTpIdx(ctx))*8
}

func (s *Symbol) Clear() {
	s.File = nil
	s.SectionFragment = nil
	s.OutputSection = nil
	s.InputSection = nil
	s.SymIdx = -1
	s.VerIdx = 0
	s.IsWeak = false
	s.IsExported = false
}

func (s *Symbol) GetRank() uint64 {
	if s.File == nil {
		return 7 << 24
	}
	return GetRank(s.File, s.ElfSym(), !s.File.IsAlive)
}
