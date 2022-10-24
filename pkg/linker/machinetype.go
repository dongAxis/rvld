package linker

import (
	"debug/elf"
	"encoding/binary"
)

type MachineType = int8

const (
	MachineTypeNone    MachineType = iota
	MachineTypeRISCV32 MachineType = iota
	MachineTypeRISCV64 MachineType = iota
)

func GetMachineTypeFromContents(contents []byte) MachineType {
	ft := GetFileType(contents)

	switch ft {
	case FileTypeObject, FileTypeDso:
		machine := binary.LittleEndian.Uint16(contents[18:])
		if machine == uint16(elf.EM_RISCV) {
			class := contents[4]
			switch class {
			case byte(elf.ELFCLASS32):
				return MachineTypeRISCV32
			case byte(elf.ELFCLASS64):
				return MachineTypeRISCV64
			}
		}
	}

	return MachineTypeNone
}

type MachineTypeStringer struct {
	MachineType
}

func (mts MachineTypeStringer) String() string {
	switch mts.MachineType {
	case MachineTypeRISCV32:
		return "riscv32"
	case MachineTypeRISCV64:
		return "riscv64"
	}
	return "none"
}
