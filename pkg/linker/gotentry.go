package linker

import "debug/elf"

type GotEntry struct {
	Idx  int64
	Val  uint64
	Type int64
}

func NewGotEntry(idx int64, val uint64, typ int64) GotEntry {
	e := GotEntry{
		Idx:  idx,
		Val:  val,
		Type: typ,
	}
	return e
}

func (e *GotEntry) IsRel() bool {
	return e.Type != int64(elf.R_RISCV_NONE)
}
