package main

// example from src/cmd/compile/abi-internal.md in golang/go
//
//go:noinline
func f(a1 uint8, a2 [2]uintptr, a3 uint8) (r1 struct {
	x uintptr
	y [2]uintptr
}, r2 string) {
	return struct {
		x uintptr
		y [2]uintptr
	}{3, [2]uintptr{5, 7}}, "a"
}

func main() {
	f(3, [2]uintptr{7, 9}, 5)
}