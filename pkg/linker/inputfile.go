package linker

import (
	"debug/elf"
	"fmt"
	"github.com/ksco/rvld/pkg/utils"
	"unsafe"
)

type InputFile struct {
	File         *File
	Symbols      []*Symbol
	ElfSections  []Shdr
	FirstGlobal  int64
	ShStrtab     []byte
	SymbolStrtab []byte

	ElfSyms  []Sym
	IsAlive  bool
	Priority uint32

	LocalSyms []Symbol
	FragSyms  []Symbol
}

func NewInputFile(file *File) *InputFile {
	f := &InputFile{File: file}
	if len(file.Contents) < int(unsafe.Sizeof(Ehdr{})) {
		utils.Fatal("file too small")
	}
	if !CheckMagic(file.Contents) {
		utils.Fatal("not an ELF file")
	}

	ehdr := utils.Read[Ehdr](file.Contents)

	contents := file.Contents[ehdr.ShOff:]
	shdr := utils.Read[Shdr](contents)

	numSections := int64(ehdr.ShNum)
	if numSections == 0 {
		numSections = int64(shdr.Size)
	}

	f.ElfSections = []Shdr{shdr}
	for numSections > 1 {
		contents = contents[unsafe.Sizeof(Shdr{}):]
		f.ElfSections = append(f.ElfSections, utils.Read[Shdr](contents))
		numSections--
	}

	shstrtabIdx := int64(ehdr.ShStrndx)
	if ehdr.ShStrndx == uint16(elf.SHN_XINDEX) {
		shstrtabIdx = int64(shdr.Link)
	}

	f.ShStrtab = f.GetBytesFromIdx(shstrtabIdx)
	return f
}

func (f *InputFile) GetBytesFromShdr(s *Shdr) []byte {
	end := s.Offset + s.Size
	if uint64(len(f.File.Contents)) < end {
		utils.Fatal(fmt.Sprintf("section header is out of range: %d", s.Offset))
	}

	return f.File.Contents[s.Offset:end]
}

func (f *InputFile) GetBytesFromIdx(idx int64) []byte {
	utils.Assert(idx < int64(len(f.ElfSections)))
	return f.GetBytesFromShdr(&f.ElfSections[idx])
}

func (f *InputFile) FillUpElfSyms(s *Shdr) {
	bs := f.GetBytesFromShdr(s)
	nums := len(bs) / int(unsafe.Sizeof(Sym{}))
	elfSyms := make([]Sym, 0)
	for nums > 0 {
		elfSyms = append(elfSyms, utils.Read[Sym](bs))
		bs = bs[unsafe.Sizeof(Sym{}):]
		nums--
	}

	f.ElfSyms = elfSyms
}

func (f *InputFile) FindSection(ty uint32) *Shdr {
	for i := 0; i < len(f.ElfSections); i++ {
		sec := &f.ElfSections[i]
		if sec.Type == ty {
			return sec
		}
	}
	return nil
}

func (f *InputFile) SwapIsAlive(isAlive bool) bool {
	old := f.IsAlive
	f.IsAlive = isAlive
	return old
}

func (f *InputFile) GetGlobalSyms() []*Symbol {
	return f.Symbols[f.FirstGlobal:]
}

func (f *InputFile) GetEhdr() Ehdr {
	return utils.Read[Ehdr](f.File.Contents)
}
