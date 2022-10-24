package linker

import (
	"github.com/ksco/rvld/pkg/utils"
	"os"
)

type File struct {
	Name     string
	Contents []byte

	Parent *File
}

func MustNewFile(filename string) *File {
	contents, err := os.ReadFile(filename)
	utils.MustNo(err)
	return &File{
		Name:     filename,
		Contents: contents,
	}
}

func OpenLibrary(path string) *File {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	file := &File{Name: path, Contents: contents}
	ty := GetMachineTypeFromContents(file.Contents)
	if ty == MachineTypeNone || ty == MachineTypeRISCV64 {
		return file
	}

	utils.Fatal("incompatible file")
	return nil
}

func FindLibrary(ctx *Context, name string) *File {
	for _, dir := range ctx.Arg.LibraryPaths {
		stem := dir + "/lib" + name
		if f := OpenLibrary(stem + ".a"); f != nil {
			return f
		}
	}

	utils.Fatal("library not found")
	return nil
}
