package linker

import "debug/elf"

func GetRank(file *ObjectFile, esym *Sym, isLazy bool) uint64 {
	if esym.IsCommon() {
		if isLazy {
			return (6 << 24) + uint64(file.Priority)
		}

		return (5 << 24) + uint64(file.Priority)
	}

	isWeak := esym.Bind() == uint8(elf.STB_WEAK)
	if isLazy {
		if isWeak {
			return (4 << 24) + uint64(file.Priority)
		}
		return (3 << 24) + uint64(file.Priority)
	}
	if isWeak {
		return (2 << 24) + uint64(file.Priority)
	}
	return (1 << 24) + uint64(file.Priority)
}
