package linker

import (
	"bytes"
	"encoding/binary"
	"github.com/ksco/rvld/pkg/utils"
	"unsafe"
)

func ReadFatArchiveMembers(file *File) []*File {
	begin := 0
	data := begin + 8
	var strTab []byte
	var files []*File

	for begin+len(file.Contents)-data >= 2 {
		if (begin-data)%2 == 1 {
			data++
		}

		hdr := &ArHdr{}
		err := binary.Read(bytes.NewBuffer(file.Contents[data:]), binary.LittleEndian, hdr)
		utils.MustNo(err)
		body := data + int(unsafe.Sizeof(ArHdr{}))
		data = body + hdr.GetSize()

		if hdr.IsStrtab() {
			strTab = file.Contents[body:data]
			continue
		}

		if hdr.IsSymtab() {
			continue
		}

		ptr := file.Contents[body:]
		name := hdr.ReadName(strTab, &ptr)

		if name == "__.SYMDEF" || name == "__.SYMDEF SORTED" {
			continue
		}

		files = append(files, &File{
			Name:     name,
			Contents: file.Contents[body:data],
			Parent:   file,
		})
	}

	return files
}

func ReadArchiveMembers(file *File) []*File {
	switch GetFileType(file.Contents) {
	case FileTypeAr:
		return ReadFatArchiveMembers(file)
	default:
		utils.Fatal("unreachable")
	}
	return nil
}
