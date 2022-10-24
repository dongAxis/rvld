package linker

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"github.com/ksco/rvld/pkg/utils"
	"unicode"
)

type FileType = int8

const (
	FileTypeUnknown FileType = iota
	FileTypeEmpty   FileType = iota
	FileTypeObject  FileType = iota
	FileTypeDso     FileType = iota
	FileTypeAr      FileType = iota
	FileTypeThinAr  FileType = iota
	FileTypeText    FileType = iota
)

func GetFileType(contents []byte) FileType {
	if len(contents) == 0 {
		return FileTypeEmpty
	}

	if CheckMagic(contents) {
		et := elf.Type(binary.LittleEndian.Uint16(contents[16:]))
		switch et {
		case elf.ET_REL:
			return FileTypeObject
		case elf.ET_DYN:
			return FileTypeDso
		}
		return FileTypeUnknown
	}

	if bytes.HasPrefix(contents, []byte("!<arch>\n")) {
		return FileTypeAr
	}
	if bytes.HasPrefix(contents, []byte("!<thin>\n")) {
		return FileTypeThinAr
	}

	isTextFile := func() bool {
		return len(contents) >= 4 &&
			unicode.IsPrint(rune(contents[0])) &&
			unicode.IsPrint(rune(contents[1])) &&
			unicode.IsPrint(rune(contents[2])) &&
			unicode.IsPrint(rune(contents[3]))
	}

	if isTextFile() {
		return FileTypeText
	}

	return FileTypeUnknown
}

func CheckFileCompatibility(ctx *Context, file *File) {
	mt := GetMachineTypeFromContents(file.Contents)
	if mt != ctx.Arg.Emulation {
		utils.Fatal("incompatible file type")
	}
}
