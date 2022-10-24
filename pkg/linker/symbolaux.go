package linker

type SymbolAux struct {
	GotIdx   int32
	GotTpIdx int32
}

func NewSymbolAux() SymbolAux {
	return SymbolAux{
		GotIdx:   -1,
		GotTpIdx: -1,
	}
}
