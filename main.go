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
)

/* TODO parse:
* extract data that is specific to just an architecture, e.g amd64 or arm64, or
  an OS, e.g windows or linux (including "unix" meta OS), and appears in all of them,
  but does not appear in "all", and extract them out for additional deduplication

* extract types from modules (*only* extract types which appear in function signatures?)

* data dedup leaves empty objects behind?

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

type dirStack struct {
	l []string
}

func (s *dirStack) pushMultiple(l []string) {
	// reverse sorted order, to pop in sorted order (not important)
	// sort.Slice(l, func(i, j int) bool { return l[j] < l[i] })
	s.l = append(s.l, l...)
}

func (s *dirStack) pop() (string, bool) {
	size := len(s.l)
	if size == 0 {
		return "", false
	}

	dir := s.l[size-1]
	s.l = s.l[:size-1]
	return dir, true
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

	st := dirStack{l: []string{"."}}

	for {
		root, success := st.pop()
		if !success {
			return
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

		st.pushMultiple(subdirs)
	}
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

type pkgData struct {
	Funcs   map[string]funcData
	Types   map[string]typeData
	Structs map[string]structDef
	Aliases map[string]alias
}

func newPkgData() pkgData {
	return pkgData{
		Funcs:   make(map[string]funcData),
		Types:   make(map[string]typeData),
		Structs: make(map[string]structDef),
		Aliases: make(map[string]alias),
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
func (x pkgData) and(y pkgData) pkgData {
	return pkgData{
		Funcs:   mapAnd(x.Funcs, y.Funcs),
		Types:   mapAnd(x.Types, y.Types),
		Structs: mapAnd(x.Structs, y.Structs),
		Aliases: mapAnd(x.Aliases, y.Aliases),
	}
}

func mapMerge[T any](x, y map[string]T) {
	for k, v := range y {
		x[k] = v
	}
}

func (x pkgData) merge(y pkgData) {
	mapMerge(x.Funcs, y.Funcs)
	mapMerge(x.Types, y.Types)
	mapMerge(x.Structs, y.Structs)
	mapMerge(x.Aliases, y.Aliases)
}

func mapNot[T any](x, y map[string]T) {
	for k := range y {
		delete(x, k)
	}
}

func (x pkgData) not(y pkgData) {
	mapNot(x.Funcs, y.Funcs)
	mapNot(x.Types, y.Types)
	mapNot(x.Structs, y.Structs)
	mapNot(x.Aliases, y.Aliases)
}

func (x pkgData) empty() bool {
	return (len(x.Funcs) + len(x.Types) + len(x.Structs) + len(x.Aliases)) == 0
}

// also handle methods
func parseFunc(obj *types.Func, pkg pkgData) {
	signature := obj.Type().(*types.Signature)
	// do not handle generic functions
	if signature.TypeParams() != nil {
		return
	}

	name := obj.FullName()

	pkg.Funcs[name] = funcData{
		Params:  tupToSlice(signature.Params(), name+"|param", pkg),
		Results: tupToSlice(signature.Results(), name+"|result", pkg),
	}
}

func parseType(obj *types.TypeName, pkg pkgData) {
	if obj.IsAlias() {
		name := fmt.Sprintf("%s.%s", obj.Pkg().Path(), obj.Name())
		pkg.Aliases[name] = alias{Target: getTypeName(obj.Type(), name, pkg)}
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
		parseStruct(getTypeName(obj.Type(), "", pkg), t, pkg)
	case *types.Interface:
		isInterface = true
	case *types.Basic:
		pkg.Types[getTypeName(obj.Type(), "", pkg)] = typeData{Underlying: getTypeName(t, "", pkg)}
	case *types.Pointer:
		doPanic := false
		switch elT := t.Elem().(type) {
		case *types.Struct:
			// *struct{}
			doPanic = elT.NumFields() != 0
		case *types.Basic:
			// runtime/defs_aix_ppc64.go: type pthread_attr *byte
			// old runtime versions: runtime/os_windows.go type stdFunction *byte
			doPanic = !(elT.Kind() == types.Byte && (named.Obj().Name() == "pthread_attr" || named.Obj().Name() == "stdFunction"))
		default:
			doPanic = true
		}
		if doPanic {
			panic(fmt.Sprintf("pkg %s, type %s", named.Obj().Pkg().Path(), named))
		}
	case *types.Array, *types.Slice, *types.Signature, *types.Map, *types.Chan:
		// nothing
	default:
		_ = named.Underlying().(*types.Basic)
		panic(named.Underlying())
	}

	if !isInterface {
		parseMethods(obj, pkg)
	}
}

// false if method comes from embedded struct field
func selfMethod(objT types.Type, f types.Object) bool {
	recvT := f.Type().(*types.Signature).Recv().Type()

	return types.Identical(recvT, objT)
}

func parseMethod(method types.Object, pkg pkgData) {
	// name format (not returned by f.Id() ):
	// value receiver: {pkg}.{receiver_type}.{method_name}, e.g main.base.xyzzy
	// pointer receiver: {pkg}.(*{receiver_type}).{method_name}, e.g main.(*base).xyzzy

	signature := method.Type().(*types.Signature)
	recvT := signature.Recv().Type()

	var recvName string

	if t, ok := recvT.Underlying().(*types.Pointer); ok {
		recvName = fmt.Sprintf("(*%s)", t.Elem().(*types.Named).Obj().Name())
	} else {
		recvName = recvT.(*types.Named).Obj().Name()
	}

	name := fmt.Sprintf("%s.%s.%s", method.Pkg().Path(), recvName, method.Name())

	baseParams := tupToSlice(signature.Params(), name+"|param", pkg)
	realParams := make([]namedType, 1, len(baseParams)+1)
	realParams[0] = namedType{
		Name:     "self",
		DataType: getTypeName(recvT, "", pkg),
	}
	realParams = append(realParams, baseParams...)

	pkg.Funcs[name] = funcData{
		Params:  realParams,
		Results: tupToSlice(signature.Results(), name+"|result", pkg),
	}
}

func tupToSlice(tup *types.Tuple, name string, pkg pkgData) []namedType {
	tupLen := tup.Len()
	out := make([]namedType, tupLen)
	for i := 0; i < tupLen; i++ {
		param := tup.At(i)

		out[i] = namedType{
			Name:     param.Name(),
			DataType: getTypeName(param.Type(), fmt.Sprintf("%s_%d", name, i), pkg),
		}
	}

	return out
}

func getTypeName(iface types.Type, name string, pkg pkgData) string {
	switch dt := iface.(type) {
	case *types.Named:
		// incorrect if the type is declared in an external package
		//return dt.Obj().Id()
		obj := dt.Obj()
		if pkg := obj.Pkg(); pkg == nil { // universe scope
			return obj.Name()
		} else {
			return fmt.Sprintf("%s.%s", obj.Pkg().Path(), obj.Name())
		}
	case *types.Basic:
		return dt.String()
	case *types.Pointer:
		return getTypeName(dt.Elem(), name+"|ptr", pkg) + "*"
	case *types.Slice:
		return getTypeName(dt.Elem(), name+"|slice", pkg) + "[]"
	case *types.Array:
		arrLen := dt.Len()
		name = fmt.Sprintf("%s|[%d]arr", name, arrLen)
		return fmt.Sprintf("%s[%d]", getTypeName(dt.Elem(), name, pkg), arrLen)
	case *types.Map:
		return "map"
	case *types.Interface:
		return "iface"
	case *types.Signature:
		return "code*"
	case *types.Chan:
		return "chan"
	case *types.Struct:
		if name == "" {
			panic(iface)
		}
		parseStruct(name, dt, pkg)
		return name
	default:
		_ = dt.(*types.Named)
		panic("unreachable")
	}
}

func parseMethods(obj *types.TypeName, pkg pkgData) {
	objT := obj.Type()
	methods := types.NewMethodSet(objT)
	numMethods := methods.Len()
	handledMethodNames := make(map[string]bool, numMethods)

	for i := 0; i < numMethods; i++ {
		method := methods.At(i).Obj()
		handledMethodNames[method.Name()] = true
		if !selfMethod(objT, method) {
			continue // comes from embedded field
		}
		parseMethod(method, pkg)
	}

	pObjT := types.NewPointer(objT)
	pMethods := types.NewMethodSet(pObjT)
	numPMethods := pMethods.Len()

	for i := 0; i < numPMethods; i++ {
		method := pMethods.At(i).Obj()
		if handledMethodNames[method.Name()] || !selfMethod(pObjT, method) {
			continue // already handled or from embedded field
		}
		parseMethod(method, pkg)
	}
}

func parseStruct(name string, obj *types.Struct, pkg pkgData) {
	numFields := obj.NumFields()
	fields := make([]namedType, numFields)
	for i := 0; i < numFields; i++ {
		field := obj.Field(i)
		// for "anonymous" struct members, e.g database/sql.Tx.stmts
		fieldPath := fmt.Sprintf("%s.%s", name, field.Name())
		fields[i] = namedType{
			Name:     field.Name(),
			DataType: getTypeName(field.Type(), fieldPath, pkg),
		}
	}
	pkg.Structs[name] = structDef{Fields: fields}
}

// extract parts common to all architectures into "all" arch
// and remove said parts from other architectures
func archSplit(pkgArchs map[string]pkgData) {
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
}

// group up results by archFilter, get items in every arch in the group, and extract to separate "arch"
func postMerge(archFilter func(string) bool, pkgArchs map[string]pkgData, name string) {
	var filtered pkgData
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
	if filtered.empty() {
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
			if strings.HasSuffix(astPkg.Name, "_test") || astPkg.Name == "builtin" || astPkg.Name == "main" {
				deletedKeys = append(deletedKeys, key)
			}
		}

		for _, key := range deletedKeys {
			delete(astPkgs, key)
		}

		if len(astPkgs) > 1 {
			fmt.Println(len(astPkgs), astPkgs)
			panic(path)
		}

		for _, astPkg := range astPkgs {
			outCh <- filterPkg(astPkg, path)
		}
	}

	wg.Done()
	wg.Wait()
	chanClose.Do(func() { close(outCh) })
}

func pkgExtract(inCh <-chan map[string]*packages.Package, outCh chan<- map[string]pkgData, chanClose *sync.Once, wg *sync.WaitGroup) {
	for pkgMap := range inCh {
		pkgArchs := make(map[string]pkgData)
		for pkgArch, pkg := range pkgMap {
			scope := pkg.Types.Scope()
			names := scope.Names()

			pkgD := newPkgData()
			for _, name := range names {
				switch obj := scope.Lookup(name).(type) {
				case *types.Func:
					parseFunc(obj, pkgD)
				case *types.TypeName:
					parseType(obj, pkgD)
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

func pkgMerge(inCh <-chan map[string]pkgData, outPath string, wg *sync.WaitGroup) {
	allPkgs := make(map[string]pkgData)

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

	wg.Done()
}

func main() {
	outPath := check1(filepath.Abs(os.Args[2]))
	check(os.Chdir(os.Args[1]))

	dirChan := make(chan string)
	pkgChan := make(chan map[string]*packages.Package)
	pkgDataChan := make(chan map[string]pkgData)

	numProcs := runtime.GOMAXPROCS(0)

	var wg, pkgParseWg, pkgExtractWg sync.WaitGroup
	pkgParseWg.Add(numProcs)
	pkgExtractWg.Add(numProcs)

	go pkgMerge(pkgDataChan, outPath, &wg)

	var pkgParseClose, pkgExtractClose sync.Once

	for i := 0; i < numProcs; i++ {
		go pkgParse(dirChan, pkgChan, &pkgParseClose, &pkgParseWg)
		go pkgExtract(pkgChan, pkgDataChan, &pkgExtractClose, &pkgExtractWg)
	}

	dirwalk(dirChan)

	// dirwalk done, start channel close chain
	wg.Add(1)
	close(dirChan)

	// wait for pkgMerge to finish
	wg.Wait()
}
