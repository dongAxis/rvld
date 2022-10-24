package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
	"runtime/debug"
	"strings"
)

type Uint interface {
	uint8 | uint16 | uint32 | uint64
}

func CountrZero[T Uint](n T) int {
	switch any(n).(type) {
	case uint8:
		return bits.TrailingZeros8(uint8(n))
	case uint16:
		return bits.TrailingZeros16(uint16(n))
	case uint32:
		return bits.TrailingZeros32(uint32(n))
	case uint64:
		return bits.TrailingZeros64(uint64(n))
	}

	Fatal("unreachable")
	return 0
}

func CountlZero[T Uint](n T) int {
	switch any(n).(type) {
	case uint8:
		return bits.LeadingZeros8(uint8(n))
	case uint16:
		return bits.LeadingZeros16(uint16(n))
	case uint32:
		return bits.LeadingZeros32(uint32(n))
	case uint64:
		return bits.LeadingZeros64(uint64(n))
	}

	Fatal("unreachable")
	return 0
}

func hasSingleBit(n uint64) bool {
	return n&(n-1) == 0
}

func BitCeil(val uint64) uint64 {
	if hasSingleBit(val) {
		return val
	}
	return 1 << (64 - CountlZero(val))
}

func MustNo(err error) {
	if err != nil {
		Fatal(err)
	}
}

func Fatal(v any) {
	fmt.Println("rvld: "+"\033[0;1;31mfatal:\033[0m", fmt.Sprintf("%s", v))
	debug.PrintStack()
	os.Exit(1)
}

func Assert(condition bool) {
	if !condition {
		Fatal("Assert failed")
	}
}

func AlignTo(val, align uint64) uint64 {
	if align == 0 {
		return val
	}
	return (val + align - 1) & ^(align - 1)
}

func AllZeros(bs []byte) bool {
	b := byte(0)
	for _, s := range bs {
		b |= s
	}
	return b == 0
}

func Read[T any](data []byte) (val T) {
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.LittleEndian, &val)
	MustNo(err)
	return
}

func Write[T any](data []byte, e T) {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, e)
	MustNo(err)
	copy(data, buf.Bytes())
}

func Bit[T Uint](val T, pos int) T {
	return (val >> pos) & 1
}

func Bits[T Uint](val T, hi T, lo T) T {
	return (val >> lo) & ((1 << (hi - lo + 1)) - 1)
}

func SignExtend(val uint64, size int) uint64 {
	return uint64(int64(val<<(63-size)) >> (63 - size))
}

func RemoveIf[T any](elems []T, condition func(T) bool) []T {
	i := 0

	for _, elem := range elems {
		if condition(elem) {
			continue
		}
		elems[i] = elem
		i++
	}
	return elems[:i]
}

func RemovePrefix(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		s = strings.TrimPrefix(s, prefix)
		return s, true
	}
	return s, false
}
