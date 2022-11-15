# rvld

English | [中文版](README_cn.md)

rvld is a minimal linker implementation for the RV64GC architecture, mainly for educational purposes. rvld mostly copied the source code of [rui314/mold](https://github.com/rui314/mold), so it is a derivative work of mold, and is also distributed under the [GNU AGPL v3 LICENSE](LICENSE).

rvld can statically link a simple C program (such as the Hello world in the example below) and produce a runnable binary.

```bash
cat <<EOF | $CC -o a.o -c -xc -static -
#include <stdio.h>
int main() {
  printf("Hello, World.\n");
  return 0;
}
EOF

$CC -B. -s -static a.o -o out
qemu-riscv64 out

# Hello, World.
```

rvld is only about 3000 lines of Go code and has no external dependencies other than the standard library. Based on this project, PLCT Lab launched an open course "Implementing a Linker from Scratch". The course is in Chinese.