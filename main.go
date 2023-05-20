package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"path/filepath"
	"runtime"
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

func getArchitectures() (out []string) {
	// TODO check ALL of this over
	out = []string{
		"darwin-amd64",
		"darwin-amd64-cgo",
		"freebsd-386",
		"freebsd-386-cgo",
		"freebsd-amd64",
		"freebsd-amd64-cgo",
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
		"linux-ppc64",
		// // added in 1.11, but this is not going to be useful here
		//"js-wasm",
	}
	version := os.Getenv("version")
	if version == "" {
		version = runtime.Version()
	}
	version = "v" + version[2:] // e.g go1.20.2 to v1.20.2

	// https://go.dev/doc/go1.1#platforms
	if semver.Compare(version, "v1.1") == -1 {
		return
	}
	out = append(out,
		"freebsd-arm", "netbsd-386", "netbsd-386-cgo", "netbsd-amd64",
		"netbsd-amd64-cgo", "netbsd-arm", "netbsd-arm-cgo", "openbsd-386", "openbsd-386-cgo",
		"openbsd-amd64", "openbsd-amd64-cgo", "linux-arm-cgo",
	)

	// ???
	if semver.Compare(version, "v1.2") == -1 {
		return
	}
	out = append(out, "dragonfly-amd64", "dragonfly-amd64-cgo")

	// https://go.dev/doc/go1.3#os
	if semver.Compare(version, "v1.3") == -1 {
		return
	}
	out = append(out, "plan9-386", "solaris-amd64")

	// https://go.dev/doc/go1.4#os
	if semver.Compare(version, "v1.4") == -1 {
		return
	}
	out = append(out,
		"android-arm", "android-arm-cgo", "plan9-amd64", "android-amd64",
		"android-amd64-cgo", "android-arm64", "android-arm64-cgo",
	)

	// https://go.dev/doc/go1.5#ports
	if semver.Compare(version, "v1.5") == -1 {
		return
	}
	out = append(out,
		"darwin-arm64", "darwin-arm64-cgo", "linux-arm64",
		"linux-arm64-cgo", "linux-ppc64le", "linux-ppc64le-cgo", "solaris-amd64-cgo",
	)

	// https://go.dev/doc/go1.6#ports
	if semver.Compare(version, "v1.6") == -1 {
		return
	}
	out = append(out,
		"linux-mips64", "linux-mips64-cgo", "linux-mips64le", "linux-mips64le-cgo",
		"android-386", "android-386-cgo",
	)

	// https://go.dev/doc/go1.7#ports
	if semver.Compare(version, "v1.7") == -1 {
		return
	}
	out = append(out, "linux-s390x", "linux-s390x-cgo", "plan9-arm")

	// https://go.dev/doc/go1.8#ports
	if semver.Compare(version, "v1.8") == -1 {
		return
	}
	out = append(out, "linux-mips", "linux-mips-cgo", "linux-mipsle", "linux-mipsle-cgo")

	// ???
	if semver.Compare(version, "v1.11") == -1 {
		return
	}
	out = append(out, "linux-riscv64")

	// https://go.dev/doc/go1.12#ports
	if semver.Compare(version, "v1.12") == -1 {
		return
	}
	// go tool dist list -json | jq '.[] | select(.CgoSupported == false and .GOARCH == "ppc64")'
	// does linux-ppc64 support CGO or not?
	out = append(out, "linux-ppc64-cgo", "windows-arm", "aix-ppc64", "openbsd-arm-cgo")

	// https://go.dev/doc/go1.13#ports
	if semver.Compare(version, "v1.13") == -1 {
		return
	}
	out = append(out,
		"aix-ppc64-cgo", "illumos-amd64", "illumos-amd64-cgo", "freebsd-arm-cgo",
		"netbsd-arm64", "netbsd-arm64-cgo", "openbsd-arm64", "openbsd-arm64-cgo",
	)

	// https://go.dev/doc/go1.14#ports
	if semver.Compare(version, "v1.14") == -1 {
		return
	}
	out = append(out, "freebsd-arm64", "freebsd-arm64-cgo")

	// https://go.dev/doc/go1.15#ports
	if semver.Compare(version, "v1.15") == -1 {
		return
	}
	out = append(out, "openbsd-arm")

	// https://go.dev/doc/go1.16#ports
	if semver.Compare(version, "v1.16") == -1 {
		return
	}
	out = append(out,
		"ios-arm64", "ios-arm64-cgo", "ios-amd64", "ios-amd64-cgo", "openbsd-mips64", "linux-riscv64-cgo",
	)

	// https://go.dev/doc/go1.17#ports
	if semver.Compare(version, "v1.17") == -1 {
		return
	}
	out = append(out, "windows-arm64", "windows-arm64-cgo", "openbsd-mips64-cgo")

	// https://go.dev/doc/go1.19#ports
	if semver.Compare(version, "v1.19") == -1 {
		return
	}
	out = append(out, "linux-loong64", "linux-loong64-cgo")

	// https://go.dev/doc/go1.20#ports
	if semver.Compare(version, "v1.20") == -1 {
		return
	}
	out = append(out, "freebsd-riscv64", "freebsd-riscv64-cgo")

	return out
}

type stack[T any] struct {
	l []T
}

func (s *stack[T]) pushMultipleRev(l []T) {
	// reverse sorted order, to pop in "the right" order
	reverseSlice(l)
	s.l = append(s.l, l...)
}

func (s *stack[T]) push(e T) {
	s.l = append(s.l, e)
}

func reverseSlice[T any](l []T) {
	length := len(l)
	for i := 0; i < length/2; i++ {
		j := length - i - 1
		l[i], l[j] = l[j], l[i]
	}
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
	out := make(map[string]map[string]bool)

	for _, architecture := range architectures {
		split := strings.Split(architecture, "-")
		archMap := make(map[string]bool, len(split))
		for _, tag := range split {
			archMap[tag] = true
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

// copy-pasted from github.com/golang/go src/go/build/syslist.go
var knownOS = map[string]bool{
	"aix":       true,
	"android":   true,
	"darwin":    true,
	"dragonfly": true,
	"freebsd":   true,
	"hurd":      true,
	"illumos":   true,
	"ios":       true,
	"js":        true,
	"linux":     true,
	"nacl":      true,
	"netbsd":    true,
	"openbsd":   true,
	"plan9":     true,
	"solaris":   true,
	"windows":   true,
	"zos":       true,
}

var knownArch = map[string]bool{
	"386":         true,
	"amd64":       true,
	"amd64p32":    true,
	"arm":         true,
	"armbe":       true,
	"arm64":       true,
	"arm64be":     true,
	"loong64":     true,
	"mips":        true,
	"mipsle":      true,
	"mips64":      true,
	"mips64le":    true,
	"mips64p32":   true,
	"mips64p32le": true,
	"ppc":         true,
	"ppc64":       true,
	"ppc64le":     true,
	"riscv":       true,
	"riscv64":     true,
	"s390":        true,
	"s390x":       true,
	"sparc":       true,
	"sparc64":     true,
	"wasm":        true,
}

// go/build/build.go goodOSArchFile
func getFilenameBuildTags(filePath string) (goos, goarch string) {
	fileName := filepath.Base(filePath)
	fileName = fileName[:len(fileName)-3]             // remove .go
	potentialTags := strings.Split(fileName, "_")[1:] // drop anything before first _

	/*
		if len(potentialTags) > 0 && potentialTags[len(potentialTags)-1] == "test" {
			potentialTags = potentialTags[:len(potentialTags)-1]
		}
	*/

	if len(potentialTags) == 0 {
		return
	}

	// get last two _-seperated elements
	if tagsNum := len(potentialTags); tagsNum > 2 {
		potentialTags = potentialTags[tagsNum-2:]
	}

	//*_GOOS
	//*_GOARCH
	//*_GOOS_GOARCH
	//*/

	last := potentialTags[len(potentialTags)-1]
	if knownOS[last] {
		goos = last
		return
	}
	if knownArch[last] {
		goarch = last
	}
	if len(potentialTags) == 2 {
		if first := potentialTags[0]; knownOS[first] {
			goos = first
		}
	}

	return
}

func commentTags(commentGroups []*ast.CommentGroup) constraint.Expr {
	for _, commentGroup := range commentGroups {
		for _, comment := range commentGroup.List {
			if maybeExpr, err := constraint.Parse(comment.Text); err == nil {
				return maybeExpr
			}
		}
	}

	return nil
}

var extraTagMap = map[string]string{
	"android": "linux",
	"illumos": "solaris",
	"ios":     "darwin",
}

func getTags(filePath string, fileObj *ast.File) constraint.Expr {
	expr := commentTags(fileObj.Comments)

	goos, goarch := getFilenameBuildTags(filePath)

	for _, tag := range []string{goos, goarch} {
		if tag == "" {
			continue
		}

		var tagExpr constraint.Expr = &constraint.TagExpr{Tag: tag}
		if extraTag, ok := extraTagMap[tag]; ok {
			tagExpr = &constraint.OrExpr{X: tagExpr, Y: &constraint.TagExpr{Tag: extraTag}}
		}

		if expr == nil {
			expr = tagExpr
		} else {
			expr = &constraint.AndExpr{X: expr, Y: tagExpr}
		}
	}

	return expr
}

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

func tagCheck(tag string, tags map[string]bool) bool {
	if tag != "unix" {
		return tags[tag]
	}

	// tags map is shorter than unixOS map
	for tag := range tags {
		if unixOS[tag] {
			return true
		}
	}
	return false
}

// parse os-arch[-cgo]
func getEnv(arch string) []string {
	out := os.Environ()
	if arch == "all" {
		return out
	}

	hasCGO := false
	for _, s := range strings.Split(arch, "-") {
		if knownArch[s] {
			out = append(out, fmt.Sprintf("GOARCH=%s", s))
		} else if knownOS[s] {
			out = append(out, fmt.Sprintf("GOOS=%s", s))
		} else if s == "cgo" {
			hasCGO = true
		} else {
			panic(arch)
		}
	}

	if !hasCGO {
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

func filterPkg(pkg *ast.Package, path string) map[string]*packages.Package {
	archMatches := map[string]bool{}

	conf := packages.Config{
		Mode:      packages.NeedTypes | packages.NeedDeps | packages.NeedImports,
		Dir:       os.Args[1],
		ParseFile: parseDiscardFuncBody,
	}

	for filePath, fileObj := range pkg.Files {
		if strings.HasSuffix(filePath, "_test.go") {
			continue
		}

		expr := getTags(filePath, fileObj)
		// no build constraints
		if expr == nil {
			archMatches["all"] = true
			continue
		}

		// identify which tag sets set in buildConstraints match
		for arch, tags := range buildConstraints {
			if expr.Eval(func(tag string) bool { return tagCheck(tag, tags) }) {
				archMatches[arch] = true
			}
		}

		// non-"all" files exist + every arch is matched by at least one file,
		// nothing more to be learned here
		if len(archMatches) == len(buildConstraints)+1 {
			break
		}
	}

	// has something for all arches and some arch-specific things
	if archMatches["all"] && len(archMatches) != 1 {
		delete(archMatches, "all")
		for arch := range buildConstraints {
			archMatches[arch] = true
		}
	}

	out := make(map[string]*packages.Package)

	for arch := range archMatches {
		conf.Env = getEnv(arch)

		newPkg := check1(packages.Load(&conf, path))
		if len(newPkg) != 1 {
			panic(len(newPkg))
		}

		out[arch] = newPkg[0]
	}

	return out
}

type namedType struct {
	Name     string
	DataType string
}

func tupleCmp(x, y []namedType) bool {
	if len(x) != len(y) {
		return false
	}
	for i, xEl := range x {
		if yEl := y[i]; xEl != yEl {
			return false
		}
	}
	return true
}

type funcData struct {
	Params  []namedType
	Results []namedType
}

func (x funcData) equals(yI equalsI) bool {
	y := yI.(funcData)
	return len(x.Params) == len(y.Params) &&
		len(x.Results) == len(y.Results) &&
		tupleCmp(x.Params, y.Params) &&
		tupleCmp(x.Results, y.Results)
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
	return tupleCmp(x.Fields, yI.(structDef).Fields)
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

type equalsI interface {
	equals(equalsI) bool
}

func mapAnd[V equalsI](x, y map[string]V) map[string]V {
	out := make(map[string]V)
	for name, xV := range x {
		if yV, ok := y[name]; ok && xV.equals(yV) {
			out[name] = xV
		}
	}
	return out
}

// get pkgData with definitions existing in both x and y
func (pkg *pkgData) and(y *pkgData) *pkgData {
	return &pkgData{
		Funcs:      mapAnd(pkg.Funcs, y.Funcs),
		Types:      mapAnd(pkg.Types, y.Types),
		Structs:    mapAnd(pkg.Structs, y.Structs),
		Aliases:    mapAnd(pkg.Aliases, y.Aliases),
		Interfaces: mapAnd(pkg.Interfaces, y.Interfaces),
	}
}

func mapMerge[T any](x, y map[string]T) {
	for k, v := range y {
		x[k] = v
	}
}

func (pkg *pkgData) merge(y *pkgData) {
	mapMerge(pkg.Funcs, y.Funcs)
	mapMerge(pkg.Types, y.Types)
	mapMerge(pkg.Structs, y.Structs)
	mapMerge(pkg.Aliases, y.Aliases)
	mapMerge(pkg.Interfaces, y.Interfaces)
}

func mapNot[T any](x, y map[string]T) {
	for k := range y {
		delete(x, k)
	}
}

func (pkg *pkgData) not(y *pkgData) {
	mapNot(pkg.Funcs, y.Funcs)
	mapNot(pkg.Types, y.Types)
	mapNot(pkg.Structs, y.Structs)
	mapNot(pkg.Aliases, y.Aliases)
	mapNot(pkg.Interfaces, y.Interfaces)
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

	pkg.Funcs[name] = funcData{
		Params:  pkg.tupToSlice(signature.Params(), name+"|param"),
		Results: pkg.tupToSlice(signature.Results(), name+"|result"),
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
			doPanic = elT.NumFields() != 0
			if !doPanic {
				// *struct{}
				pkg.Types[name] = typeData{Underlying: "byte*"}
			}
		case *types.Basic:
			pkg.Types[name] = typeData{Underlying: elT.Name() + "*"}
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

	pkg.Funcs[name] = funcData{
		Params:  realParams,
		Results: pkg.tupToSlice(signature.Results(), name+"|result"),
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
		if pkg := obj.Pkg(); pkg == nil {
			// universe scope
			return obj.Name()
		}
		// full package path
		return fmt.Sprintf("%s.%s", obj.Pkg().Path(), obj.Name())
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
	for _, method := range typeutil.IntuitiveMethodSet(obj.Type(), nil) {
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

	// does not have at least one element on every arch, skip
	if len(pkgArchs) != len(buildConstraints) {
		return
	}

	postMerge(func(string) bool { return true }, pkgArchs, "all")
	postMerge(func(arch string) bool { split := strings.Split(arch, "-"); return split[len(split)-1] == "cgo" }, pkgArchs, "cgo")
	postMerge(func(arch string) bool { split := strings.Split(arch, "-"); return split[len(split)-1] != "cgo" }, pkgArchs, "nocgo")
	postMerge(func(arch string) bool { return unixOS[strings.Split(arch, "-")[0]] }, pkgArchs, "unix")

	for archStr := range knownArch {
		postMerge(func(arch string) bool {
			split := strings.Split(arch, "-")
			return len(split) > 1 && split[1] == archStr
		}, pkgArchs, archStr)
	}

	for osStr := range knownOS {
		postMerge(func(arch string) bool { return strings.Split(arch, "-")[0] == osStr }, pkgArchs, osStr)
		postMerge(func(arch string) bool {
			split := strings.Split(arch, "-")
			return split[0] == osStr && split[len(split)-1] == "cgo"
		}, pkgArchs, osStr+"-cgo")
	}

	// additional cleanup of empty architectures
	var emptyKeys []string

	for arch, pkgD := range pkgArchs {
		if pkgD.empty() {
			emptyKeys = append(emptyKeys, arch)
		}
	}

	for _, key := range emptyKeys {
		delete(pkgArchs, key)
	}
}

// group up results by archFilter, get items in every arch in the group, and extract to separate "arch"
func postMerge(archFilter func(string) bool, pkgArchs map[string]*pkgData, name string) {
	var filtered *pkgData
	firstPkg := true

	for arch, pkgD := range pkgArchs {
		if !archFilter(arch) {
			continue
		}

		if firstPkg {
			filtered = pkgD
			firstPkg = false
		} else {
			filtered = filtered.and(pkgD)
		}
	}

	// found nothing
	if firstPkg || filtered.empty() {
		return
	}

	var emptyKeys []string

	// remove duplicates
	for arch, pkgD := range pkgArchs {
		if archFilter(arch) {
			pkgD.not(filtered)
			if pkgD.empty() {
				emptyKeys = append(emptyKeys, arch)
			}
		}
	}

	for _, key := range emptyKeys {
		delete(pkgArchs, key)
	}

	pkgArchs[name] = filtered
}

func pkgParse(inCh <-chan string, outCh chan<- map[string]*packages.Package, chanClose *sync.Once, wg *sync.WaitGroup) {
	fset := token.NewFileSet()
	for path := range inCh {
		astPkgs := check1(parser.ParseDir(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments))

		var deletedKeys []string
		for key, astPkg := range astPkgs {
			if strings.HasSuffix(astPkg.Name, "_test") || astPkg.Name == "builtin" {
				deletedKeys = append(deletedKeys, key)
			}
		}

		for _, key := range deletedKeys {
			delete(astPkgs, key)
		}

		for _, astPkg := range astPkgs {
			outCh <- filterPkg(astPkg, path)
		}
	}

	wg.Done()
	wg.Wait()
	chanClose.Do(func() { close(outCh) })
}

func pkgExtract(inCh <-chan map[string]*packages.Package, outCh chan<- map[string]*pkgData, chanClose *sync.Once, wg *sync.WaitGroup) {
	for pkgMap := range inCh {
		pkgArchs := make(map[string]*pkgData)
		for pkgArch, pkg := range pkgMap {
			pkgD := newPkgData()
			for _, pkgDef := range typeutil.Dependencies(pkg.Types) {
				scope := pkgDef.Scope()
				names := scope.Names()
				for _, name := range names {
					switch obj := scope.Lookup(name).(type) {
					case *types.Func:
						pkgD.parseFunc(obj)
					case *types.TypeName:
						pkgD.parseType(obj)
					}
				}
			}

			pkgArchs[pkgArch] = pkgD
		}

		archSplit(pkgArchs)
		outCh <- pkgArchs
	}

	wg.Done()
	wg.Wait()
	chanClose.Do(func() { close(outCh) })
}

func pkgMerge(inCh <-chan map[string]*pkgData, outPath string) {
	allPkgs := make(map[string]*pkgData)

	for pkgArchs := range inCh {
		for arch, pkg := range pkgArchs {
			if _, ok := allPkgs[arch]; !ok {
				allPkgs[arch] = newPkgData()
			}
			allPkgs[arch].merge(pkg)
		}
	}

	data := check1(json.Marshal(allPkgs))

	check(os.WriteFile(outPath, data, 0o666))
}

const BUFSIZE = 1000

func main() {
	outPath := check1(filepath.Abs(os.Args[2]))
	check(os.Chdir(os.Args[1]))

	dirChan := make(chan string, BUFSIZE)
	pkgChan := make(chan map[string]*packages.Package, BUFSIZE)
	pkgDataChan := make(chan map[string]*pkgData, BUFSIZE)

	numProcs := runtime.GOMAXPROCS(0)

	var pkgParseClose, pkgExtractClose sync.Once
	var pkgParseWg, pkgExtractWg sync.WaitGroup
	pkgParseWg.Add(numProcs)
	pkgExtractWg.Add(numProcs)

	go dirwalk(dirChan)

	for i := 0; i < numProcs; i++ {
		go pkgParse(dirChan, pkgChan, &pkgParseClose, &pkgParseWg)
		go pkgExtract(pkgChan, pkgDataChan, &pkgExtractClose, &pkgExtractWg)
	}

	pkgMerge(pkgDataChan, outPath)
}
