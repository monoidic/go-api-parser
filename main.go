package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"golang.org/x/mod/semver"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/types/typeutil"
)

/* TODO parse:
* more/better dedup groups in archSplit?

  * handle type aliased structs, e.g internal/fuzz.CorpusEntry, better,
  instead of creating a bunch of anonymous struct definitions everywhere they appear
  in function signatures or in structs
*/

// everything:  go tool dist list -json | jq -r '.[] | "\u0022" + .GOOS + "-" + .GOARCH + "\u0022,"'
var architectures = getArchitectures()
var architectureSet = makeSet(architectures)

type Set[T comparable] struct {
	m map[T]struct{}
}

func (s Set[T]) Contains(e T) bool {
	_, ok := s.m[e]
	return ok
}

func makeSet[T comparable](arr []T) Set[T] {
	m := make(map[T]struct{})
	for _, e := range arr {
		m[e] = struct{}{}
	}
	return Set[T]{m: m}
}

// getArchitectures generates a list of architectures supported by the
// specific version of Go specified in the "version" environment variable.
// It covers Go versions from 1.1 up to 1.20, and for each version,
// it appends the architectures introduced in that version to the list.
//
// The function uses semantic versioning to compare Go versions. If the
// specified Go version is older than the version currently considered in the function,
// the function will not include the architectures introduced in and after the considered version.
//
// The list of architectures is constructed based on the Go release notes
// (https://go.dev/doc/devel/release), with a few exceptions marked with TODOs.
func getArchitectures() (out []string) {
	// TODO check ALL of this over
	out = []string{
		"darwin-amd64",
		"darwin-amd64-cgo",
		/*
			"freebsd-386",
			"freebsd-386-cgo",
			"freebsd-amd64",
			"freebsd-amd64-cgo",
		*/
		"linux-386",
		"linux-386-cgo",
		"windows-386",
		"windows-386-cgo",
		"windows-amd64",
		"windows-amd64-cgo",
		"linux-amd64",
		"linux-amd64-cgo",
		// should be fine above here
		// TODO track these down somehow
		/*"linux-ppc64",*/
		// // added in 1.11, but this is not going to be useful here
		//"js-wasm",
	}

	versionTable := []struct {
		version string
		archs   []string
	}{
		{
			// https://go.dev/doc/go1.1#platforms
			version: "v1.1",
			archs: []string{
				/*"freebsd-arm", "netbsd-386", "netbsd-386-cgo", "netbsd-amd64",
				"netbsd-amd64-cgo", "netbsd-arm", "netbsd-arm-cgo", "openbsd-386", "openbsd-386-cgo",
				"openbsd-amd64", "openbsd-amd64-cgo", "linux-arm", "linux-arm-cgo",
				*/
				"linux-arm", "linux-arm-cgo",
			}},
		{
			// ???
			version: "v1.2",
			archs:   []string{ /*"dragonfly-amd64", "dragonfly-amd64-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.3#os
			version: "v1.3",
			archs:   []string{ /*"plan9-386", "solaris-amd64"*/ },
		},
		{
			// https://go.dev/doc/go1.4#os
			version: "v1.4",
			archs:   []string{
				/*
					"android-arm", "android-arm-cgo", "plan9-amd64", "android-amd64",
					"android-amd64-cgo", "android-arm64", "android-arm64-cgo",
				*/
			},
		},
		{
			// https://go.dev/doc/go1.5#ports
			version: "v1.5",
			archs: []string{
				/*
					"darwin-arm64", "darwin-arm64-cgo", "linux-arm64",
					"linux-arm64-cgo", "linux-ppc64le", "linux-ppc64le-cgo", "solaris-amd64-cgo",
				*/
				"darwin-arm64", "darwin-arm64-cgo", "linux-arm64", "linux-arm64-cgo",
			},
		},
		{
			// https://go.dev/doc/go1.6#ports
			version: "v1.6",
			archs:   []string{
				/*
					"linux-mips64", "linux-mips64-cgo", "linux-mips64le", "linux-mips64le-cgo",
					"android-386", "android-386-cgo",
				*/
			},
		},
		{
			// https://go.dev/doc/go1.7#ports
			version: "v1.7",
			archs:   []string{ /*"linux-s390x", "linux-s390x-cgo", "plan9-arm"*/ },
		},
		{
			// https://go.dev/doc/go1.8#ports
			version: "v1.8",
			archs:   []string{ /*"linux-mips", "linux-mips-cgo", "linux-mipsle", "linux-mipsle-cgo"*/ },
		},
		{
			// ???
			version: "v1.11",
			archs:   []string{ /*"linux-riscv64"*/ },
		},
		{
			// https://go.dev/doc/go1.12#ports
			version: "v1.12",
			// go tool dist list -json | jq '.[] | select(.CgoSupported == false and .GOARCH == "ppc64")'
			// does linux-ppc64 support CGO or not?
			archs: []string{ /*"linux-ppc64-cgo", "windows-arm", "aix-ppc64", "openbsd-arm-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.13#ports
			version: "v1.13",
			archs:   []string{
				/*
					"aix-ppc64-cgo", "illumos-amd64", "illumos-amd64-cgo", "freebsd-arm-cgo",
					"netbsd-arm64", "netbsd-arm64-cgo", "openbsd-arm64", "openbsd-arm64-cgo",
				*/
			},
		},
		{
			// https://go.dev/doc/go1.14#ports
			version: "v1.14",
			archs:   []string{ /*"freebsd-arm64", "freebsd-arm64-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.15#ports
			version: "v1.15",
			archs:   []string{ /*"openbsd-arm"*/ },
		},
		{
			// https://go.dev/doc/go1.16#ports
			version: "v1.16",
			archs:   []string{
				/*"ios-arm64", "ios-arm64-cgo", "ios-amd64", "ios-amd64-cgo", "openbsd-mips64", "linux-riscv64-cgo",*/
			},
		},
		{
			// https://go.dev/doc/go1.17#ports
			version: "v1.17",
			archs:   []string{ /*"windows-arm64", "windows-arm64-cgo", "openbsd-mips64-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.19#ports
			version: "v1.19",
			archs:   []string{ /*"linux-loong64", "linux-loong64-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.20#ports
			version: "v1.20",
			archs:   []string{ /*"freebsd-riscv64", "freebsd-riscv64-cgo"*/ },
		},
		// wasip1-wasm added in 1.21, but not interesting here
	}
	version := os.Getenv("version")
	if version == "" {
		version = runtime.Version()
	}
	version = "v" + version[2:] // e.g go1.20.2 to v1.20.2

	for _, entry := range versionTable {
		if semver.Compare(version, entry.version) == -1 {
			return
		}

		out = append(out, entry.archs...)
	}

	return out
}

type stack[T any] struct {
	l []T
}

func (s *stack[T]) pushMultipleRev(l []T) {
	// reverse sorted order, to pop in "the right" order
	slices.Reverse(l)
	s.l = append(s.l, l...)
}

func (s *stack[T]) push(e T) {
	s.l = append(s.l, e)
}

func (s *stack[T]) pop() (T, bool) {
	var top T
	size := len(s.l)
	if size == 0 {
		return top, false
	}

	top = s.l[size-1]
	s.l = s.l[:size-1]
	return top, true
}

func getBuildConstraints() map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(architectures))

	for _, architecture := range architectures {
		split := strings.Split(architecture, "-")
		archMap := make(map[string]bool)
		for _, tag := range split {
			archMap[tag] = true
			if unixOS[tag] {
				archMap["unix"] = true
			}
		}
		out[architecture] = archMap
	}

	return out
}

var buildConstraints = getBuildConstraints()

func check(err error) {
	if err != nil {
		log.Panicln(err)
	}
}

func check1[T any](arg1 T, err error) T {
	check(err)
	return arg1
}

var filteredDirs = map[string]bool{
	"testdata": true,
	"vendor":   true,
	"cmd":      true,
	".git":     true,
}

func dirwalk(ch chan<- string) {

	var st stack[string]
	st.push(".")

	for {
		root, success := st.pop()
		if !success {
			break
		}
		ch <- root

		var subdirs []string

		for _, entry := range check1(os.ReadDir(root)) {
			if !entry.IsDir() {
				continue
			}
			dirName := entry.Name()
			if !filteredDirs[dirName] {
				subdirs = append(subdirs, filepath.Join(root, dirName))
			}
		}

		st.pushMultipleRev(subdirs)
	}

	close(ch)
}

// from github.com/golang/go src/go/build/syslist.go
var knownOS = []string{
	"aix",
	"android",
	"darwin",
	"dragonfly",
	"freebsd",
	"hurd",
	"illumos",
	"ios",
	"js",
	"linux",
	"nacl",
	"netbsd",
	"openbsd",
	"plan9",
	"solaris",
	"wasip1",
	"windows",
	"zos",
}

var knownOSSet = makeSet(knownOS)

var knownArch = []string{
	"386",
	"amd64",
	"amd64p32",
	"arm",
	"armbe",
	"arm64",
	"arm64be",
	"loong64",
	"mips",
	"mipsle",
	"mips64",
	"mips64le",
	"mips64p32",
	"mips64p32le",
	"ppc",
	"ppc64",
	"ppc64le",
	"riscv",
	"riscv64",
	"s390",
	"s390x",
	"sparc",
	"sparc64",
	"wasm",
}

var knownArchSet = makeSet(knownArch)

// from src/cmd/dist/build.go
var unixOS = map[string]bool{
	"aix":       true,
	"android":   true,
	"darwin":    true,
	"dragonfly": true,
	"freebsd":   true,
	"hurd":      true,
	"illumos":   true,
	"ios":       true,
	"linux":     true,
	"netbsd":    true,
	"openbsd":   true,
	"solaris":   true,
}

// parse os-arch[-cgo]
func getEnv(arch string) []string {
	out := os.Environ()
	if arch == "all" {
		return append(out, "GOARCH=amd64", "GOOS=linux", "CGO_ENABLED=0")
	}

	hasCGO := false
	for _, s := range strings.Split(arch, "-") {
		if knownArchSet.Contains(s) {
			out = append(out, fmt.Sprintf("GOARCH=%s", s))
		} else if knownOSSet.Contains(s) {
			out = append(out, fmt.Sprintf("GOOS=%s", s))
		} else if s == "cgo" {
			hasCGO = true
		} else {
			panic(arch)
		}
	}

	if hasCGO {
		out = append(out, "CGO_ENABLED=1")
	} else {
		out = append(out, "CGO_ENABLED=0")
	}

	return out
}

func parseDiscardFuncBody(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
	f, err := parser.ParseFile(fset, filename, src, 0)

	for _, decl := range f.Decls {
		if funcDecl, ok := decl.(*ast.FuncDecl); ok {
			funcDecl.Body = nil
		}
	}

	return f, err
}

type buildInfo struct {
	arch string
	path string
}

type pkgArch struct {
	pkg  *types.Package
	arch string
}

type pkgDataArch struct {
	pkgD *pkgData
	arch string
}

type namedType struct {
	Name     string
	DataType string
}

type funcData struct {
	Params  []namedType
	Results []namedType
}

func (x funcData) equals(yI equalsI) bool {
	y := yI.(funcData)
	return len(x.Params) == len(y.Params) &&
		len(x.Results) == len(y.Results) &&
		slices.Equal(x.Params, y.Params) &&
		slices.Equal(x.Results, y.Results)
}

type typeData struct {
	Underlying string
}

func (x typeData) equals(yI equalsI) bool {
	return x == yI.(typeData)
}

type structDef struct {
	Fields []namedType
}

func (x structDef) equals(yI equalsI) bool {
	return slices.Equal(x.Fields, yI.(structDef).Fields)
}

type alias struct {
	Target string
}

func (x alias) equals(yI equalsI) bool {
	return x == yI.(alias)
}

type iface struct{}

func (x iface) equals(yI equalsI) bool {
	return x == yI.(iface)
}

type pkgData struct {
	Funcs      map[string]funcData
	Types      map[string]typeData
	Structs    map[string]structDef
	Aliases    map[string]alias
	Interfaces map[string]iface
}

func newPkgData() *pkgData {
	return &pkgData{
		Funcs:      make(map[string]funcData),
		Types:      make(map[string]typeData),
		Structs:    make(map[string]structDef),
		Aliases:    make(map[string]alias),
		Interfaces: make(map[string]iface),
	}
}

func (pkgD *pkgData) Clone() *pkgData {
	return &pkgData{
		Funcs:      maps.Clone(pkgD.Funcs),
		Types:      maps.Clone(pkgD.Types),
		Structs:    maps.Clone(pkgD.Structs),
		Aliases:    maps.Clone(pkgD.Aliases),
		Interfaces: maps.Clone(pkgD.Interfaces),
	}
}

type equalsI interface {
	equals(equalsI) bool
}

func MapAnd[V equalsI](x, y map[string]V) map[string]V {
	out := make(map[string]V)
	if len(x) > len(y) {
		// swap to iterate over shorter map
		// (order is irrelevant here)
		x, y = y, x
	}
	for name, xV := range x {
		if yV, ok := y[name]; ok && xV.equals(yV) {
			out[name] = xV
		}
	}

	return out
}

func MapAndIn[V equalsI](x, y map[string]V) {
	for name, xV := range x {
		if yV, ok := y[name]; !(ok && xV.equals(yV)) {
			delete(x, name)
		}
	}
}

// get pkgData with definitions existing in both pkg And y
func (pkg *pkgData) And(y *pkgData) *pkgData {
	return &pkgData{
		Funcs:      MapAnd(pkg.Funcs, y.Funcs),
		Types:      MapAnd(pkg.Types, y.Types),
		Structs:    MapAnd(pkg.Structs, y.Structs),
		Aliases:    MapAnd(pkg.Aliases, y.Aliases),
		Interfaces: MapAnd(pkg.Interfaces, y.Interfaces),
	}
}

// in-place and
func (pkg *pkgData) AndIn(y *pkgData) {
	MapAndIn(pkg.Funcs, y.Funcs)
	MapAndIn(pkg.Types, y.Types)
	MapAndIn(pkg.Structs, y.Structs)
	MapAndIn(pkg.Aliases, y.Aliases)
	MapAndIn(pkg.Interfaces, y.Interfaces)
}

func MapAndNot[V equalsI](x, y map[string]V) map[string]V {
	out := make(map[string]V)
	for name, xV := range x {
		if yV, ok := y[name]; !(ok && xV.equals(yV)) {
			out[name] = xV
		}
	}

	return out
}

func MapAndNotIn[V equalsI](x, y map[string]V) {
	for name, xV := range x {
		if yV, ok := y[name]; ok && xV.equals(yV) {
			delete(x, name)
		}
	}
}

// return map with key-value pairs from pkg that do not have an equal pair in y
func (pkg *pkgData) AndNot(y *pkgData) *pkgData {
	return &pkgData{
		Funcs:      MapAndNot(pkg.Funcs, y.Funcs),
		Types:      MapAndNot(pkg.Types, y.Types),
		Structs:    MapAndNot(pkg.Structs, y.Structs),
		Aliases:    MapAndNot(pkg.Aliases, y.Aliases),
		Interfaces: MapAndNot(pkg.Interfaces, y.Interfaces),
	}
}

// in-place version of andNot
func (pkg *pkgData) AndNotIn(y *pkgData) {
	MapAndNotIn(pkg.Funcs, y.Funcs)
	MapAndNotIn(pkg.Types, y.Types)
	MapAndNotIn(pkg.Structs, y.Structs)
	MapAndNotIn(pkg.Aliases, y.Aliases)
	MapAndNotIn(pkg.Interfaces, y.Interfaces)
}

func MapMerge[T any](x, y map[string]T) map[string]T {
	out := maps.Clone(x)
	maps.Copy(out, y)
	return out
}

// return merged map with both x and y
func (pkg *pkgData) Merge(y *pkgData) *pkgData {
	return &pkgData{
		Funcs:      MapMerge(pkg.Funcs, y.Funcs),
		Types:      MapMerge(pkg.Types, y.Types),
		Structs:    MapMerge(pkg.Structs, y.Structs),
		Aliases:    MapMerge(pkg.Aliases, y.Aliases),
		Interfaces: MapMerge(pkg.Interfaces, y.Interfaces),
	}
}

// in-place version of merge
func (pkg *pkgData) MergeIn(y *pkgData) {
	maps.Copy(pkg.Funcs, y.Funcs)
	maps.Copy(pkg.Types, y.Types)
	maps.Copy(pkg.Structs, y.Structs)
	maps.Copy(pkg.Aliases, y.Aliases)
	maps.Copy(pkg.Interfaces, y.Interfaces)
}

func mapNot[T any](x, y map[string]T) map[string]T {
	out := make(map[string]T)
	for k, v := range x {
		if _, ok := y[k]; !ok {
			out[k] = v
		}
	}

	return out
}

func mapNotIn[T any](x, y map[string]T) {
	for k := range y {
		delete(x, k)
	}
}

// remove keys existing in y from pkg
func (pkg *pkgData) Not(y *pkgData) *pkgData {
	return &pkgData{
		Funcs:      mapNot(pkg.Funcs, y.Funcs),
		Types:      mapNot(pkg.Types, y.Types),
		Structs:    mapNot(pkg.Structs, y.Structs),
		Aliases:    mapNot(pkg.Aliases, y.Aliases),
		Interfaces: mapNot(pkg.Interfaces, y.Interfaces),
	}
}

func (pkg *pkgData) NotIn(y *pkgData) {
	mapNotIn(pkg.Funcs, y.Funcs)
	mapNotIn(pkg.Types, y.Types)
	mapNotIn(pkg.Structs, y.Structs)
	mapNotIn(pkg.Aliases, y.Aliases)
	mapNotIn(pkg.Interfaces, y.Interfaces)
}

func (pkg *pkgData) empty() bool {
	return (len(pkg.Funcs) + len(pkg.Types) + len(pkg.Structs) + len(pkg.Aliases) + len(pkg.Interfaces)) == 0
}

// also handle methods
func (pkg *pkgData) parseFunc(obj *types.Func) {
	signature := obj.Type().(*types.Signature)
	// do not handle generic functions
	if signature.TypeParams() != nil {
		return
	}

	name := obj.FullName()

	params := pkg.tupToSlice(signature.Params(), name+"|param")
	results := pkg.tupToSlice(signature.Results(), name+"|result")

	pkg.Funcs[name] = funcData{
		Params:  params,
		Results: results,
	}
}

func (pkg *pkgData) parseType(obj *types.TypeName) {
	name := fmt.Sprintf("%s.%s", obj.Pkg().Path(), obj.Name())
	if obj.IsAlias() {
		pkg.Aliases[name] = alias{Target: pkg.getTypeName(obj.Type(), name)}
		return
	}

	named, ok := obj.Type().(*types.Named)
	if !ok {
		if obj.Pkg().Name() == "unsafe" && obj.Name() == "Pointer" {
			return
		}
		panic(obj)
	}
	// do not handle generic types
	if named.TypeParams() != nil {
		return
	}

	isInterface := false

	switch t := named.Underlying().(type) {
	case *types.Struct:
		pkg.parseStruct(pkg.getTypeName(obj.Type(), ""), t)
	case *types.Interface:
		isInterface = true
	case *types.Basic:
		pkg.Types[pkg.getTypeName(obj.Type(), "")] = typeData{Underlying: pkg.getTypeName(t, "")}
	case *types.Pointer:
		doPanic := false
		switch elT := t.Elem().(type) {
		case *types.Struct:
			if elT.NumFields() == 0 {
				// *struct{}
				pkg.Types[name] = typeData{Underlying: "byte*"}
			} else {
				doPanic = true
			}
		case *types.Basic:
			pkg.Types[name] = typeData{Underlying: elT.Name() + "*"}
		case *types.Named:
			elTO := elT.Obj()
			childName := fmt.Sprintf("%s.%s", elTO.Pkg().Path(), elTO.Name())
			pkg.Types[name] = typeData{Underlying: childName + "*"}
		default:
			doPanic = true
		}
		if doPanic {
			panic(fmt.Sprintf("pkg %s, type %s", named.Obj().Pkg().Path(), named))
		}
	case *types.Array, *types.Slice, *types.Map, *types.Chan, *types.Signature:
		pkg.Types[name] = typeData{Underlying: pkg.getTypeName(t, name)}
	default:
		_ = named.Underlying().(*types.Basic)
	}

	if isInterface {
		pkg.Interfaces[name] = iface{}
	} else {
		pkg.parseMethods(obj)
	}
}

// false if method comes from embedded struct field
func selfMethod(objT types.Type, f types.Object) bool {
	recvT := f.Type().(*types.Signature).Recv().Type()

	return types.Identical(recvT, objT) || types.Identical(recvT, types.NewPointer(objT))
}

func (pkg *pkgData) parseMethod(method types.Object) {
	signature := method.Type().(*types.Signature)
	recvT := signature.Recv().Type()

	var recvName string

	if t, ok := recvT.Underlying().(*types.Pointer); ok {
		// value receiver: {pkg}.{receiver_type}.{method_name}, e.g main.base.xyzzy
		recvName = fmt.Sprintf("(*%s)", t.Elem().(*types.Named).Obj().Name())
	} else {
		// pointer receiver: {pkg}.(*{receiver_type}).{method_name}, e.g main.(*base).xyzzy
		recvName = recvT.(*types.Named).Obj().Name()
	}

	name := fmt.Sprintf("%s.%s.%s", method.Pkg().Path(), recvName, method.Name())

	baseParams := pkg.tupToSlice(signature.Params(), name+"|param")
	realParams := make([]namedType, 1, len(baseParams)+1)
	realParams[0] = namedType{
		Name:     "self",
		DataType: pkg.getTypeName(recvT, ""),
	}
	realParams = append(realParams, baseParams...)

	results := pkg.tupToSlice(signature.Results(), name+"|result")

	pkg.Funcs[name] = funcData{
		Params:  realParams,
		Results: results,
	}
}

func (pkg *pkgData) tupToSlice(tup *types.Tuple, name string) []namedType {
	tupLen := tup.Len()
	out := make([]namedType, tupLen)
	for i := 0; i < tupLen; i++ {
		param := tup.At(i)

		out[i] = namedType{
			Name:     param.Name(),
			DataType: pkg.getTypeName(param.Type(), fmt.Sprintf("%s_%d", name, i)),
		}
	}

	return out
}

func (pkg *pkgData) getTypeName(iface types.Type, name string) string {
	switch dt := iface.(type) {
	case *types.Named:
		obj := dt.Obj()
		pkg := obj.Pkg()
		if pkg == nil {
			// universe scope
			return obj.Name()
		}
		// full package path
		return fmt.Sprintf("%s.%s", pkg.Path(), obj.Name())
	case *types.Basic:
		return dt.String()
	case *types.Pointer:
		return pkg.getTypeName(dt.Elem(), name+"|ptr") + "*"
	case *types.Slice:
		return pkg.getTypeName(dt.Elem(), name+"|slice") + "[]"
	case *types.Array:
		arrLen := dt.Len()
		name = fmt.Sprintf("%s|[%d]arr", name, arrLen)
		return fmt.Sprintf("%s[%d]", pkg.getTypeName(dt.Elem(), name), arrLen)
	case *types.Map:
		return "map"
	case *types.Interface:
		return "iface"
	case *types.Signature:
		return "code*"
	case *types.Chan:
		return "chan"
	case *types.Struct:
		// need name here to uniquely identify this anonymous struct
		if name == "" {
			panic(iface)
		}
		pkg.parseStruct(name, dt)
		return name
	default:
		_ = dt.(*types.Named)
		panic("unreachable")
	}
}

func (pkg *pkgData) parseMethods(obj *types.TypeName) {
	objT := obj.Type()
	for _, method := range typeutil.IntuitiveMethodSet(objT, nil) {
		methodO := method.Obj()
		if selfMethod(objT, methodO) {
			pkg.parseMethod(methodO)
		}
	}
}

func (pkg *pkgData) parseStruct(name string, obj *types.Struct) {
	numFields := obj.NumFields()
	fields := make([]namedType, numFields)
	for i := 0; i < numFields; i++ {
		field := obj.Field(i)
		// for "anonymous" struct members, e.g database/sql.Tx.stmts
		fieldPath := fmt.Sprintf("%s.%s", name, field.Name())
		fields[i] = namedType{
			Name:     field.Name(),
			DataType: pkg.getTypeName(field.Type(), fieldPath),
		}
	}
	pkg.Structs[name] = structDef{Fields: fields}
}

// extract parts common to subsets of architectures into separate architecture
// and remove said parts from the constituent architectures of the group
func archSplit(pkgArchs map[string]*pkgData) {
	// only has "all" architecture, skip
	if _, hasAll := pkgArchs["all"]; hasAll {
		if len(pkgArchs) != 1 {
			panic(0)
		}
		return
	}

	postMerge(func(arch string) bool { return true }, pkgArchs, "all")

	for _, sl := range [][]string{{"unix"}, knownOS, knownArch, {"cgo"}} {
		for _, tagStr := range sl {
			postMerge(func(arch string) bool { return buildConstraints[arch][tagStr] }, pkgArchs, tagStr)
		}
	}

	for _, sl := range [][]string{knownOS, knownArch} {
		for _, tagStr := range sl {
			postMerge(func(arch string) bool {
				tags := buildConstraints[arch]
				return tags[tagStr] && tags["cgo"]
			}, pkgArchs, tagStr+"-cgo")
		}
	}
}

// group up results by archFilter, get items in every arch in the group, and extract to separate "arch"
func postMerge(archFilter func(string) bool, pkgArchs map[string]*pkgData, name string) {
	var filtered *pkgData

	for arch, pkgD := range pkgArchs {
		if !(architectureSet.Contains(arch) && archFilter(arch)) {
			continue
		}

		if filtered == nil {
			filtered = pkgD.Clone()
		} else {
			filtered.AndIn(pkgD)
		}

		if filtered.empty() {
			// found nothing
			return
		}
	}

	if filtered == nil {
		// found nothing
		return
	}

	// remove false positives
	for arch, pkgD := range pkgArchs {
		if !(architectureSet.Contains(arch) && !archFilter(arch)) {
			continue
		}
		filtered.AndNotIn(pkgD)
		if filtered.empty() {
			// only false positives
			return
		}
	}

	// remove duplicates
	for arch, pkgD := range pkgArchs {
		if !(architectureSet.Contains(arch) && archFilter(arch)) {
			continue
		}
		pkgD.NotIn(filtered)
		if pkgD.empty() {
			delete(pkgArchs, arch)
		}
	}

	pkgArchs[name] = filtered
}

func pkgFilter(inCh <-chan string, outCh chan<- buildInfo, wg *sync.WaitGroup) {
	fset := token.NewFileSet()
	for path := range inCh {
		astPkgs := check1(parser.ParseDir(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments))

		for key, astPkg := range astPkgs {
			if strings.HasSuffix(astPkg.Name, "_test") || astPkg.Name == "builtin" {
				delete(astPkgs, key)
			}
		}

		if len(astPkgs) == 0 {
			continue
		}

		for _, arch := range architectures {
			outCh <- buildInfo{arch: arch, path: path}
		}
	}

	wg.Done()
}

func pkgBuild(inCh <-chan buildInfo, outCh chan<- pkgArch, wg *sync.WaitGroup) {
	conf := packages.Config{
		Mode:      packages.NeedTypes | packages.NeedDeps | packages.NeedImports,
		Dir:       os.Args[1],
		ParseFile: parseDiscardFuncBody,
	}

	for bi := range inCh {
		conf.Env = getEnv(bi.arch)
		newPkg := check1(packages.Load(&conf, bi.path))
		if len(newPkg) != 1 {
			panic(len(newPkg))
		}
		outCh <- pkgArch{pkg: newPkg[0].Types, arch: bi.arch}
	}

	wg.Done()
}

// also filters dupes
func pkgDeps(inCh <-chan pkgArch, outCh chan<- pkgArch, wg *sync.WaitGroup) {
	for pa := range inCh {
		for _, dep := range typeutil.Dependencies(pa.pkg) {
			key := fmt.Sprintf("%s-%s", dep.Path(), pa.arch)
			if !pkgSeen(key) {
				outCh <- pkgArch{pkg: dep, arch: pa.arch}
			}
		}
	}

	wg.Done()
}

func pkgExtract(inCh <-chan pkgArch, outCh chan<- pkgDataArch, wg *sync.WaitGroup) {
	for pa := range inCh {
		pkgD := newPkgData()
		scope := pa.pkg.Scope()
		for _, name := range scope.Names() {
			switch obj := scope.Lookup(name).(type) {
			case *types.Func:
				pkgD.parseFunc(obj)
			case *types.TypeName:
				pkgD.parseType(obj)
			}
		}

		outCh <- pkgDataArch{pkgD: pkgD, arch: pa.arch}
	}

	wg.Done()
}

var pkgSeenMap sync.Map

func pkgSeen(key string) bool {
	_, alreadyPresent := pkgSeenMap.Swap(key, struct{}{})
	return alreadyPresent
}

func pkgMerge(inCh <-chan pkgDataArch, outPath string) {
	allPkgs := make(map[string]*pkgData, len(buildConstraints))
	for _, arch := range architectures {
		allPkgs[arch] = newPkgData()
	}

	for pa := range inCh {
		allPkgs[pa.arch].MergeIn(pa.pkgD)
	}

	archSplit(allPkgs)

	for arch, pkgD := range allPkgs {
		if pkgD.empty() {
			delete(allPkgs, arch)
		}
	}

	data := check1(json.Marshal(allPkgs))
	check(os.WriteFile(outPath, data, 0o666))
}

func closeChanWait[T any](wg *sync.WaitGroup, ch chan T) {
	wg.Wait()
	close(ch)
}

const BUFSIZE = 1000

func main() {
	outPath := check1(filepath.Abs(os.Args[2]))
	check(os.Chdir(os.Args[1]))

	dirChan := make(chan string, BUFSIZE)
	filteredChan := make(chan buildInfo, BUFSIZE)
	buildChan := make(chan pkgArch, BUFSIZE)
	depsChan := make(chan pkgArch, BUFSIZE)
	extractedChan := make(chan pkgDataArch, BUFSIZE)

	numProcs := runtime.GOMAXPROCS(0)

	var pkgParseWg, buildWg, depsWg, pkgExtractWg sync.WaitGroup
	for _, wg := range []*sync.WaitGroup{&pkgParseWg, &buildWg, &depsWg, &pkgExtractWg} {
		wg.Add(numProcs)
	}

	go dirwalk(dirChan)

	for i := 0; i < numProcs; i++ {
		go pkgFilter(dirChan, filteredChan, &pkgParseWg)
		go pkgBuild(filteredChan, buildChan, &buildWg)
		go pkgDeps(buildChan, depsChan, &depsWg)
		go pkgExtract(depsChan, extractedChan, &pkgExtractWg)
	}

	go closeChanWait(&pkgParseWg, filteredChan)
	go closeChanWait(&buildWg, buildChan)
	go closeChanWait(&depsWg, depsChan)
	go closeChanWait(&pkgExtractWg, extractedChan)

	pkgMerge(extractedChan, outPath)
}
