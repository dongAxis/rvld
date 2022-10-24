package linker

import "github.com/ksco/rvld/pkg/utils"

type ContextArg struct {
	Output    string
	Emulation MachineType

	LibraryPaths []string
}

type Context struct {
	Arg ContextArg

	SymbolMap map[string]*Symbol

	SymbolsAux []SymbolAux

	Ehdr *OutputEhdr
	Shdr *OutputShdr
	Phdr *OutputPhdr
	Got  *GotSection

	Buf []byte

	FilePriority int64
	Visited      utils.MapSet[string]

	Objs []*ObjectFile

	InternalObj   *ObjectFile
	InternalEsyms []Sym

	Chunks []Chunker

	MergedSections []*MergedSection
	OutputSections []*OutputSection

	DefaultVersion uint16

	TpAddr uint64

	__InitArrayStart    *Symbol
	__InitArrayEnd      *Symbol
	__FiniArrayStart    *Symbol
	__FiniArrayEnd      *Symbol
	__PreinitArrayStart *Symbol
	__PreinitArrayEnd   *Symbol
	__GlobalPointer     *Symbol
}

func NewContext() *Context {
	return &Context{
		Arg: ContextArg{
			Emulation: MachineTypeNone,
			Output:    "a.out",
		},
		SymbolMap:      make(map[string]*Symbol),
		Visited:        utils.NewMapSet[string](),
		FilePriority:   10000,
		DefaultVersion: VER_NDX_LOCAL,
	}
}
