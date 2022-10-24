package linker

import "github.com/ksco/rvld/pkg/utils"

func ReadInputFiles(ctx *Context, args []string) {
	for _, arg := range args {
		var ok bool
		if arg, ok = utils.RemovePrefix(arg, "-l"); ok {
			ReadFile(ctx, FindLibrary(ctx, arg))
		} else {
			ReadFile(ctx, MustNewFile(arg))
		}
	}

	if len(ctx.Objs) == 0 {
		utils.Fatal("no input files")
	}
}

func ReadFile(ctx *Context, file *File) {
	if ctx.Visited.Contains(file.Name) {
		return
	}

	ft := GetFileType(file.Contents)
	switch ft {
	case FileTypeObject:
		ctx.Objs = append(ctx.Objs, CreateObjectFile(ctx, file, ""))
	case FileTypeThinAr, FileTypeAr:
		for _, child := range ReadArchiveMembers(file) {
			switch GetFileType(child.Contents) {
			case FileTypeObject:
				ctx.Objs = append(ctx.Objs, CreateObjectFile(ctx, child, file.Name))
			default:
				utils.Fatal("unknown file type")
			}
		}
		ctx.Visited.Add(file.Name)
	default:
		utils.Fatal("unknown file type")
	}
}

func CreateObjectFile(ctx *Context, file *File, archiveName string) *ObjectFile {
	CheckFileCompatibility(ctx, file)

	inLib := len(archiveName) > 0
	obj := NewObjectFile(file, inLib)
	obj.Priority = uint32(ctx.FilePriority)
	ctx.FilePriority++

	obj.parse(ctx)
	return obj
}
