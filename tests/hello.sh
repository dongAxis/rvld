#!/bin/bash

set -e

test_name=$(basename "$0" .sh)
t=out/tests/$test_name

mkdir -p "$t"

cat <<EOF | $CC -o "$t"/a.o -c -xc -static -
#include <stdio.h>
int main() {
  printf("Hello, World.\n");
  return 0;
}
EOF

$CC -B. -s -static "$t"/a.o -o "$t"/out
file "$t"/out
qemu-riscv64 "$t"/out