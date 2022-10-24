package linker

import (
	"debug/elf"
	"fmt"
	"github.com/ksco/rvld/pkg/utils"
	"math"
	"unsafe"
)

type InputSection struct {
	File          *ObjectFile
	OutputSection *OutputSection
	Contents      []byte
	Deltas        []int32
	Offset        uint32
	Shndx         uint32
	RelsecIdx     uint32
	ShSize        uint32
	IsAlive       bool
	P2Align       uint8
	Rels          []Rela
}

func NewInputSection(
	ctx *Context, file *ObjectFile, name string, shndx int64,
) *InputSection {
	s := &InputSection{
		Offset:    math.MaxUint32,
		Shndx:     math.MaxUint32,
		RelsecIdx: math.MaxUint32,
		ShSize:    math.MaxUint32,
		IsAlive:   true,
	}
	s.File = file
	s.Shndx = uint32(shndx)

	shdr := s.Shdr()
	if shndx < int64(len(file.ElfSections)) {
		s.Contents = file.File.Contents[shdr.Offset : shdr.Offset+shdr.Size]
	}

	toP2Align := func(alignment uint64) int64 {
		if alignment == 0 {
			return 0
		}
		return int64(utils.CountrZero[uint64](alignment))
	}

	if shdr.Flags&uint64(elf.SHF_COMPRESSED) != 0 {
		chdr := s.Chdr()
		s.ShSize = uint32(chdr.Size)
		s.P2Align = uint8(toP2Align(chdr.AddrAlign))
	} else {
		s.ShSize = uint32(shdr.Size)
		s.P2Align = uint8(toP2Align(shdr.AddrAlign))
	}

	s.OutputSection =
		GetOutputSectionInstance(ctx, name, uint64(shdr.Type), shdr.Flags)

	return s
}

func (s *InputSection) Shdr() *Shdr {
	if s.Shndx < uint32(len(s.File.ElfSections)) {
		return &s.File.ElfSections[s.Shndx]
	}

	utils.Fatal("unreachable")
	return nil
}

func (s *InputSection) Chdr() Chdr {
	return utils.Read[Chdr](s.Contents)
}

func (s *InputSection) GetAddr() uint64 {
	return s.OutputSection.Shdr.Addr + uint64(s.Offset)
}

func (s *InputSection) Name() string {
	if uint32(len(s.File.ElfSections)) <= s.Shndx {
		return ".common"
	}
	return getName(s.File.ShStrtab, s.File.ElfSections[s.Shndx].Name)
}

func (s *InputSection) GetRels() []Rela {
	if s.RelsecIdx == math.MaxUint32 || s.Rels != nil {
		return s.Rels
	}

	bs := s.File.GetBytesFromShdr(&s.File.InputFile.ElfSections[s.RelsecIdx])
	nums := len(bs) / int(unsafe.Sizeof(Rela{}))
	s.Rels = make([]Rela, 0)
	for nums > 0 {
		s.Rels = append(s.Rels, utils.Read[Rela](bs))
		bs = bs[unsafe.Sizeof(Rela{}):]
		nums--
	}

	return s.Rels
}

func (s *InputSection) ScanRelocations(ctx *Context) {
	utils.Assert(s.Shdr().Flags&uint64(elf.SHF_ALLOC) != 0)

	rels := s.GetRels()
	for i := 0; i < len(rels); i++ {
		rel := &rels[i]
		if rel.Type == uint32(elf.R_RISCV_NONE) {
			continue
		}

		sym := s.File.Symbols[rel.Sym]
		if sym.File == nil {
			utils.Fatal(fmt.Sprintf("undefined symbol: %s", sym.Name))
		}

		switch elf.R_RISCV(rel.Type) {
		case elf.R_RISCV_32, elf.R_RISCV_HI20, elf.R_RISCV_64:
			// Do nothing.
		case elf.R_RISCV_32_PCREL, elf.R_RISCV_TLS_GD_HI20:
			utils.Fatal("unreachable")
		case elf.R_RISCV_CALL, elf.R_RISCV_CALL_PLT:
			// Do nothing.
		case elf.R_RISCV_GOT_HI20:
			sym.Flags |= NEEDS_GOT
		case elf.R_RISCV_TLS_GOT_HI20:
			sym.Flags |= NEEDS_GOTTP
		case elf.R_RISCV_BRANCH, elf.R_RISCV_JAL, elf.R_RISCV_PCREL_HI20,
			elf.R_RISCV_PCREL_LO12_I, elf.R_RISCV_PCREL_LO12_S, elf.R_RISCV_LO12_I,
			elf.R_RISCV_LO12_S, elf.R_RISCV_TPREL_HI20, elf.R_RISCV_TPREL_LO12_I,
			elf.R_RISCV_TPREL_LO12_S, elf.R_RISCV_TPREL_ADD, elf.R_RISCV_ADD8,
			elf.R_RISCV_ADD16, elf.R_RISCV_ADD32, elf.R_RISCV_ADD64,
			elf.R_RISCV_SUB8, elf.R_RISCV_SUB16, elf.R_RISCV_SUB32,
			elf.R_RISCV_SUB64, elf.R_RISCV_ALIGN, elf.R_RISCV_RVC_BRANCH,
			elf.R_RISCV_RVC_JUMP, elf.R_RISCV_RELAX, elf.R_RISCV_SUB6,
			elf.R_RISCV_SET6, elf.R_RISCV_SET8, elf.R_RISCV_SET16,
			elf.R_RISCV_SET32:
			break
		default:
			utils.Fatal("unknown relocation")
		}
	}
}

func (s *InputSection) GetPriority() int64 {
	return (int64(s.File.Priority) << 32) | int64(s.Shndx)
}

func (s *InputSection) WriteTo(ctx *Context, buf []byte) {
	if s.Shdr().Type == uint32(elf.SHT_NOBITS) || s.ShSize == 0 {
		return
	}

	s.CopyContents(ctx, buf)

	if s.Shdr().Flags&uint64(elf.SHF_ALLOC) != 0 {
		s.ApplyRelocAlloc(ctx, buf)
	}
}

func (s *InputSection) CopyContents(ctx *Context, buf []byte) {
	if len(s.Deltas) == 0 {
		copy(buf, s.Contents)
		return
	}

	rels := s.GetRels()
	pos := uint64(0)
	for i := 0; i < len(rels); i++ {
		delta := s.Deltas[i+1] - s.Deltas[i]
		if delta == 0 {
			continue
		}
		utils.Assert(delta > 0)

		r := rels[i]
		copy(buf, s.Contents[pos:r.Offset])
		buf = buf[r.Offset-pos:]
		pos = r.Offset + uint64(delta)
	}

	copy(buf, s.Contents[pos:])
}

func itype(val uint32) uint32 {
	return val << 20
}
func stype(val uint32) uint32 {
	return utils.Bits(val, 11, 5)<<25 | utils.Bits(val, 4, 0)<<7
}

func btype(val uint32) uint32 {
	return utils.Bit(val, 12)<<31 | utils.Bits(val, 10, 5)<<25 |
		utils.Bits(val, 4, 1)<<8 | utils.Bit(val, 11)<<7
}

func utype(val uint32) uint32 {
	return (val + 0x800) & 0xffff_f000
}

func jtype(val uint32) uint32 {
	return utils.Bit(val, 20)<<31 | utils.Bits(val, 10, 1)<<21 |
		utils.Bit(val, 11)<<20 | utils.Bits(val, 19, 12)<<12
}

func cbtype(val uint16) uint16 {
	return utils.Bit(val, 8)<<12 | utils.Bit(val, 4)<<11 | utils.Bit(val, 3)<<10 |
		utils.Bit(val, 7)<<6 | utils.Bit(val, 6)<<5 | utils.Bit(val, 2)<<4 |
		utils.Bit(val, 1)<<3 | utils.Bit(val, 5)<<2
}

func cjtype(val uint16) uint16 {
	return utils.Bit(val, 11)<<12 | utils.Bit(val, 4)<<11 | utils.Bit(val, 9)<<10 |
		utils.Bit(val, 8)<<9 | utils.Bit(val, 10)<<8 | utils.Bit(val, 6)<<7 |
		utils.Bit(val, 7)<<6 | utils.Bit(val, 3)<<5 | utils.Bit(val, 2)<<4 |
		utils.Bit(val, 1)<<3 | utils.Bit(val, 5)<<2
}

func writeItype(loc []byte, val uint32) {
	mask := uint32(0b000000_00000_11111_111_11111_1111111)
	utils.Write[uint32](loc, (utils.Read[uint32](loc)&mask)|itype(val))
}

func writeStype(loc []byte, val uint32) {
	mask := uint32(0b000000_11111_11111_111_00000_1111111)
	utils.Write[uint32](loc, (utils.Read[uint32](loc)&mask)|stype(val))
}

func writeBtype(loc []byte, val uint32) {
	mask := uint32(0b000000_11111_11111_111_00000_1111111)
	utils.Write[uint32](loc, (utils.Read[uint32](loc)&mask)|btype(val))
}

func writeUtype(loc []byte, val uint32) {
	mask := uint32(0b000000_00000_00000_000_11111_1111111)
	utils.Write[uint32](loc, (utils.Read[uint32](loc)&mask)|utype(val))
}

func writeJtype(loc []byte, val uint32) {
	mask := uint32(0b000000_00000_00000_000_11111_1111111)
	utils.Write[uint32](loc, (utils.Read[uint32](loc)&mask)|jtype(val))
}

func writeCbtype(loc []byte, val uint16) {
	mask := uint16(0b111_000_111_00000_11)
	utils.Write[uint16](loc, (utils.Read[uint16](loc)&mask)|cbtype(val))
}

func writeCjtype(loc []byte, val uint16) {
	mask := uint16(0b111_00000000000_11)
	utils.Write[uint16](loc, (utils.Read[uint16](loc)&mask)|cjtype(val))
}

func setRs1(loc []byte, rs1 uint32) {
	utils.Write[uint32](loc, utils.Read[uint32](loc)&0b111111_11111_00000_111_11111_1111111)
	utils.Write[uint32](loc, utils.Read[uint32](loc)|(rs1<<15))
}

func (s *InputSection) ApplyRelocAlloc(ctx *Context, base []byte) {
	rels := s.GetRels()

	getDelta := func(idx int) int32 {
		if len(s.Deltas) == 0 {
			return 0
		}
		return s.Deltas[idx]
	}

	for i := 0; i < len(rels); i++ {
		rel := rels[i]
		if rel.Type == uint32(elf.R_RISCV_NONE) || rel.Type == uint32(elf.R_RISCV_RELAX) {
			continue
		}

		sym := s.File.Symbols[rel.Sym]
		offset := rel.Offset - uint64(getDelta(i))
		loc := base[offset:]

		if sym.File == nil {
			utils.Fatal(fmt.Sprintf("undefined symbol: %s", sym.Name))
		}

		S := sym.GetAddr(ctx)
		A := uint64(rel.Addend)
		P := s.GetAddr() + offset
		G := uint64(sym.GetGotIdx(ctx) * 8)
		GOT := ctx.Got.Shdr.Addr

		switch elf.R_RISCV(rel.Type) {
		case elf.R_RISCV_32:
			utils.Write[uint32](loc, uint32(S+A))
		case elf.R_RISCV_64:
			utils.Write[uint64](loc, S+A)
		case elf.R_RISCV_BRANCH:
			val := S + A - P
			writeBtype(loc, uint32(val))
		case elf.R_RISCV_JAL:
			val := S + A - P
			writeJtype(loc, uint32(val))
		case elf.R_RISCV_CALL, elf.R_RISCV_CALL_PLT:
			val := uint32(0)
			if !sym.ElfSym().IsUndefWeak() {
				val = uint32(S + A - P)
			}
			writeUtype(loc, val)
			writeItype(loc[4:], val)
		case elf.R_RISCV_GOT_HI20:
			utils.Write[uint32](loc, uint32(G+GOT+A-P))
		case elf.R_RISCV_TLS_GOT_HI20:
			utils.Write[uint32](loc, uint32(sym.GetGotTpAddr(ctx)+A-P))
		case elf.R_RISCV_TLS_GD_HI20:
			utils.Fatal("unreachable")
		case elf.R_RISCV_PCREL_HI20:
			utils.Write[uint32](loc, uint32(S+A-P))
		case elf.R_RISCV_HI20:
			writeUtype(loc, uint32(S+A))
		case elf.R_RISCV_LO12_I, elf.R_RISCV_LO12_S:
			val := S + A
			if rel.Type == uint32(elf.R_RISCV_LO12_I) {
				writeItype(loc, uint32(val))
			} else {
				writeStype(loc, uint32(val))
			}

			if utils.SignExtend(val, 11) == val {
				setRs1(loc, 0)
			}
		case elf.R_RISCV_TPREL_HI20:
			writeUtype(loc, uint32(S+A-ctx.TpAddr))
		case elf.R_RISCV_TPREL_ADD:
			break
		case elf.R_RISCV_TPREL_LO12_I, elf.R_RISCV_TPREL_LO12_S:
			val := S + A - ctx.TpAddr
			if rel.Type == uint32(elf.R_RISCV_TPREL_LO12_I) {
				writeItype(loc, uint32(val))
			} else {
				writeStype(loc, uint32(val))
			}

			if utils.SignExtend(val, 11) == val {
				setRs1(loc, 4)
			}
		case elf.R_RISCV_ADD8:
			utils.Write[uint8](loc, utils.Read[uint8](loc)+uint8(S+A))
		case elf.R_RISCV_ADD16:
			utils.Write[uint16](loc, utils.Read[uint16](loc)+uint16(S+A))
		case elf.R_RISCV_ADD32:
			utils.Write[uint32](loc, utils.Read[uint32](loc)+uint32(S+A))
		case elf.R_RISCV_ADD64:
			utils.Write[uint64](loc, utils.Read[uint64](loc)+uint64(S+A))
		case elf.R_RISCV_SUB8:
			utils.Write[uint8](loc, utils.Read[uint8](loc)-uint8(S+A))
		case elf.R_RISCV_SUB16:
			utils.Write[uint16](loc, utils.Read[uint16](loc)-uint16(S+A))
		case elf.R_RISCV_SUB32:
			utils.Write[uint32](loc, utils.Read[uint32](loc)-uint32(S+A))
		case elf.R_RISCV_SUB64:
			utils.Write[uint64](loc, utils.Read[uint64](loc)-uint64(S+A))
		case elf.R_RISCV_ALIGN:
			paddingSize := int64(utils.AlignTo(P, utils.BitCeil(uint64(rel.Addend+1))) - P)

			idx := int64(0)
			for ; idx < paddingSize-4; idx += 4 {
				utils.Write[uint32](loc[idx:], uint32(0x0000_0013)) // nop
			}
			if idx != paddingSize {
				utils.Write[uint16](loc[idx:], uint16(0x0001)) // c.nop
			}
		case elf.R_RISCV_RVC_BRANCH:
			val := S + A - P
			writeCbtype(loc, uint16(val))
		case elf.R_RISCV_RVC_JUMP:
			val := S + A - P
			writeCjtype(loc, uint16(val))
		case elf.R_RISCV_SUB6, elf.R_RISCV_SET6, elf.R_RISCV_SET8, elf.R_RISCV_SET16, elf.R_RISCV_SET32, elf.R_RISCV_32_PCREL:
			utils.Fatal("unreachable")
		case elf.R_RISCV_PCREL_LO12_I, elf.R_RISCV_PCREL_LO12_S:
		default:
			utils.Fatal("unreachable")
		}
	}

	for i := 0; i < len(rels); i++ {
		switch elf.R_RISCV(rels[i].Type) {
		case elf.R_RISCV_PCREL_LO12_I, elf.R_RISCV_PCREL_LO12_S:
			sym := s.File.Symbols[rels[i].Sym]
			utils.Assert(sym.InputSection == s)
			loc := base[rels[i].Offset-uint64(getDelta(i)):]
			val := utils.Read[uint32](base[sym.Value:])

			if rels[i].Type == uint32(elf.R_RISCV_PCREL_LO12_I) {
				writeItype(loc, val)
			} else {
				writeStype(loc, val)
			}
		}
	}

	for i := 0; i < len(rels); i++ {
		switch elf.R_RISCV(rels[i].Type) {
		case elf.R_RISCV_GOT_HI20, elf.R_RISCV_PCREL_HI20, elf.R_RISCV_TLS_GOT_HI20, elf.R_RISCV_TLS_GD_HI20:
			loc := base[rels[i].Offset-uint64(getDelta(i)):]
			val := utils.Read[uint32](loc)
			utils.Write[uint32](loc, utils.Read[uint32](s.Contents[rels[i].Offset:]))
			writeUtype(loc, val)
		}
	}
}

func (s *InputSection) GetFragment(rel *Rela) (*SectionFragment, uint32) {
	esym := &s.File.ElfSyms[rel.Sym]
	if esym.Type() == uint8(elf.STT_SECTION) {
		m := s.File.MergeableSections[s.File.GetShndx(esym, int64(rel.Sym))]
		return m.GetFragment(uint32(esym.Val) + uint32(rel.Addend))
	}
	return nil, 0
}
