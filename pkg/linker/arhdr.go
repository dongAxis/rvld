package linker

import (
	"bytes"
	"github.com/ksco/rvld/pkg/utils"
	"strconv"
	"strings"
)

type ArHdr struct {
	Name [16]byte
	Date [12]byte
	Uid  [6]byte
	Gid  [6]byte
	Mode [8]byte
	Size [10]byte
	Fmag [2]byte
}

func (a *ArHdr) StartsWith(s string) bool {
	return string(a.Name[:len(s)]) == s
}

func (a *ArHdr) IsStrtab() bool {
	return a.StartsWith("// ")
}

func (a *ArHdr) IsSymtab() bool {
	return a.StartsWith("/ ") || a.StartsWith("/SYM64/ ")
}

func (a *ArHdr) ReadName(strTab []byte, ptr *[]byte) string {
	// BSD-style long filename
	if a.StartsWith("#1/") {
		nameLen, err := strconv.Atoi(strings.TrimSpace(string(a.Name[3:])))
		utils.MustNo(err)
		name := (*ptr)[:nameLen]
		*ptr = (*ptr)[nameLen:]

		if end := bytes.Index(name, []byte{0}); end != -1 {
			name = name[:end]
		}
		return string(name)
	}

	// SysV-style long filename
	if a.StartsWith("/") {
		start, err := strconv.Atoi(strings.TrimSpace(string(a.Name[1:])))
		utils.MustNo(err)
		end := start + bytes.Index(strTab[start:], []byte("/\n"))
		return string(strTab[start:end])
	}

	// Short filename
	if end := bytes.Index(a.Name[:], []byte("/")); end != -1 {
		return string(a.Name[:end])
	}
	return string(a.Name[:])
}

func (a *ArHdr) GetSize() int {
	sz, err := strconv.Atoi(strings.TrimSpace(string(a.Size[:])))
	utils.MustNo(err)
	return sz
}
