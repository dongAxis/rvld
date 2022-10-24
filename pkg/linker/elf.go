package linker

import (
	"bytes"
	"debug/elf"
)

const SHF_EXCLUDE uint32 = 0x80000000
const SHT_LLVM_ADDRSIG uint32 = 0x6fff4c03
const VER_NDX_LOCAL uint16 = 0
const EF_RISCV_RVC uint32 = 1

const PageSize = 4096
const ImageBase uint64 = 0x200000

type Ehdr struct {
	Ident     [16]uint8
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint64
	PhOff     uint64
	ShOff     uint64
	Flags     uint32
	EhSize    uint16
	PhEntSize uint16
	PhNum     uint16
	ShEntSize uint16
	ShNum     uint16
	ShStrndx  uint16
}

type Shdr struct {
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	AddrAlign uint64
	EntSize   uint64
}

type Phdr struct {
	Type     uint32
	Flags    uint32
	Offset   uint64
	VAddr    uint64
	PAddr    uint64
	FileSize uint64
	MemSize  uint64
	Align    uint64
}

type Sym struct {
	Name  uint32
	Info  uint8
	Other uint8
	Shndx uint16
	Val   uint64
	Size  uint64
}

func (s *Sym) IsUndef() bool {
	return s.Shndx == uint16(elf.SHN_UNDEF)
}

func (s *Sym) IsDefined() bool {
	return !s.IsUndef()
}

func (s *Sym) IsCommon() bool {
	return s.Shndx == uint16(elf.SHN_COMMON)
}

func (s *Sym) IsAbs() bool {
	return s.Shndx == uint16(elf.SHN_ABS)
}

func (s *Sym) IsWeak() bool {
	return s.Bind() == uint8(elf.STB_WEAK)
}

func (s *Sym) IsUndefWeak() bool {
	return s.IsUndef() && s.IsWeak()
}

func (s *Sym) Type() uint8 {
	return s.Info & 0xf
}

func (s *Sym) SetType(typ uint8) {
	s.Info = (s.Info & 0xf0) | (typ & 0xf)
}

func (s *Sym) Bind() uint8 {
	return s.Info >> 4
}
func (s *Sym) SetBind(bind uint8) {
	s.Info = (s.Info & 0xf) | (bind & 0xf0)
}

func (s *Sym) StVisibility() uint8 {
	return s.Other & 0b11
}

func (s *Sym) SetVisibility(v uint8) {
	s.Other = (s.Other & 0b11111100) | (v & 0b11)
}

type Rela struct {
	Offset uint64
	Type   uint32
	Sym    uint32
	Addend int64
}

type Chdr struct {
	Type      uint32
	Reserved  uint32
	Size      uint64
	AddrAlign uint64
}

func getName(strTab []byte, offset uint32) string {
	length := bytes.Index(strTab[offset:], []byte{0})
	return string(strTab[offset : offset+uint32(length)])
}

func writeString(buf []byte, str string) int64 {
	copy(buf, str)
	buf[len(str)] = 0
	return int64(len(str)) + 1
}
