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
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
)

/* TODO parse:
 * interfaces (???)
 * functions (add to Funcs map)

 * handle type aliased structs, e.g internal/fuzz.CorpusEntry, better
 */

// go tool dist list -json | jq -r '.[] | select(.FirstClass == true) | .GOOS + "-" + .GOARCH'
var architectures = []string{
	"darwin-amd64",
	"darwin-arm64",
	"linux-386",
	"linux-amd64",
	"linux-arm",
	"linux-arm64",
	"windows-386",
	"windows-amd64",
}

func getBuildConstraints() map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(architectures)*2)

	for _, architectureBase := range architectures {
		for _, architecture := range []string{architectureBase, architectureBase + "-cgo"} {
			split := strings.Split(architectureBase, "-")
			archMap := make(map[string]bool, len(split))
			for _, tag := range split {
				archMap[tag] = true
			}
			out[architecture] = archMap
		}
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

func walkTreeDirs(ch chan<- string, root string) {
	ch <- root

	var dirNames []string

	for _, dir := range check1(os.ReadDir(root)) {
		if dir.IsDir() {
			dirName := dir.Name()
			if !filteredDirs[dirName] {
				dirNames = append(dirNames, filepath.Join(root, dir.Name()))
			}
		}
	}

	sort.Strings(dirNames)

	for _, path := range dirNames {
		walkTreeDirs(ch, path)
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

func getFilenameBuildTags(filePath string) (goos, goarch string) {
	fileName := filepath.Base(filePath)
	fileName = fileName[:len(fileName)-3]             // remove .go
	potentialTags := strings.Split(fileName, "_")[1:] // drop anything before first _
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

func getTags(filePath string, fileObj *ast.File) constraint.Expr {
	var expr constraint.Expr
tagsLoop:
	for _, commentGroup := range fileObj.Comments {
		for _, comment := range commentGroup.List {
			if maybeExpr, err := constraint.Parse(comment.Text); err == nil {
				expr = maybeExpr
				break tagsLoop
			}
		}
	}

	goos, goarch := getFilenameBuildTags(filePath)

	for _, tag := range []string{goos, goarch} {
		if tag == "" {
			continue
		}
		tagExpr := &constraint.TagExpr{Tag: tag}
		if expr == nil {
			expr = tagExpr
		} else {
			expr = &constraint.AndExpr{X: expr, Y: tagExpr}
		}
	}

	return expr
}

// parse os-arch[-cgo]
func getEnv(arch string) []string {
	out := os.Environ()
	if arch == "all" {
		return out
	}
	split := strings.Split(arch, "-")
	out = append(out, fmt.Sprintf("GOOS=%s", split[0]), fmt.Sprintf("GOARCH=%s", split[1]))
	if len(split) == 2 { // no cgo
		out = append(out, "CGO_ENABLED=0")
	}

	return out
}

func parseDiscardFuncBody(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
	f, err := parser.ParseFile(fset, filename, src, parser.AllErrors)

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
			if expr.Eval(func(tag string) bool { return tags[tag] }) {
				archMatches[arch] = true
			}
		}

		// non-"all" files exist + every arch is matched by at least one file,
		// nothing more to be learned here
		if len(archMatches) == len(buildConstraints)+1 {
			break
		}
	}

	// arch-specific stuff crops up at least once, "all" would just be a duplicate here
	if archMatches["all"] && len(archMatches) > 1 {
		delete(archMatches, "all")
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
		if structDef, ok := t.Elem().(*types.Struct); !(ok && structDef.NumFields() == 0) {
			panic(t)
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
func selfMethod(objT types.Type, f *types.Func) bool {
	recvT := f.Type().(*types.Signature).Recv().Type()

	// pointers may not equal-compare true; if only one of the two is a pointer, they don't match,
	// if both are pointers, repeatedly deref both to get the base type
	for {
		objPtr, objIsPtr := objT.Underlying().(*types.Pointer)
		recvPtr, recvIsPtr := recvT.Underlying().(*types.Pointer)
		if objIsPtr != recvIsPtr {
			return false
		}

		if !objIsPtr {
			break
		}

		objT = objPtr.Elem()
		recvT = recvPtr.Elem()
	}

	return recvT == objT
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

	baseParams := tupToSlice(signature.Params(), name+".param", pkg)
	realParams := make([]namedType, 1, len(baseParams)+1)
	realParams[0] = namedType{
		Name:     "self",
		DataType: getTypeName(recvT, "", pkg),
	}
	realParams = append(realParams, baseParams...)

	pkg.Funcs[name] = funcData{
		Params:  realParams,
		Results: tupToSlice(signature.Results(), name+".result", pkg),
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
		if !selfMethod(objT, method.(*types.Func)) {
			continue // comes from embedded field
		}
		parseMethod(method, pkg)
	}

	pObjT := types.NewPointer(objT)
	pMethods := types.NewMethodSet(pObjT)
	numPMethods := pMethods.Len()

	for i := 0; i < numPMethods; i++ {
		method := pMethods.At(i).Obj()
		if handledMethodNames[method.Name()] || !selfMethod(pObjT, method.(*types.Func)) {
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
	_, hasAll := pkgArchs["all"]
	if hasAll && len(pkgArchs) == 1 {
		return
	}

	// does not have at least one element on every arch (excluding "all"), skip
	numArchs := len(pkgArchs)
	if hasAll {
		numArchs--
	}
	if numArchs == len(buildConstraints) {
		return
	}

	// get data that is common between all architectures
	var pkgAllArch pkgData
	firstPkg := true
	for _, pkg := range pkgArchs {
		if !firstPkg {
			pkgAllArch = pkgAllArch.and(pkg)
		} else {
			pkgAllArch = pkg
			firstPkg = false
		}
	}

	// remove common parts from all architectures
	var emptyKeys []string
	for key, pkg := range pkgArchs {
		pkg.not(pkgAllArch)
		if pkg.empty() {
			emptyKeys = append(emptyKeys, key)
		}
	}

	// remove architectures that have no unique parts left
	for _, key := range emptyKeys {
		delete(pkgArchs, key)
	}

	// add common parts back as "all" architecture
	if !pkgAllArch.empty() {
		pkgArchs["all"].merge(pkgAllArch)
	}
}

func walkPrint(ch <-chan string, wg *sync.WaitGroup) {
	fset := token.NewFileSet()
	allPkgs := make(map[string]pkgData)
	for arch := range buildConstraints {
		allPkgs[arch] = newPkgData()
	}
	allPkgs["all"] = newPkgData()

	for path := range ch {
		x := check1(parser.ParseDir(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments))

		for _, astPkg := range x {
			if strings.HasSuffix(astPkg.Name, "_test") || astPkg.Name == "builtin" || astPkg.Name == "main" {
				continue
			}

			//if path == "internal/syscall/windows" {
			//if path == "internal/fuzz" {
			if true {
				pkgMap := filterPkg(astPkg, path)
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

				for arch, pkg := range pkgArchs {
					allPkgs[arch].merge(pkg)
				}
			}
		}
	}
	fmt.Println(string(check1(json.Marshal(allPkgs))))
	wg.Done()
}

func main() {
	//outPath := check1(filepath.Abs("out.json"))
	check(os.Chdir(os.Args[1]))

	ch := make(chan string, 10)

	var wg sync.WaitGroup
	wg.Add(1)
	go walkPrint(ch, &wg)
	walkTreeDirs(ch, ".")
	close(ch)
	wg.Wait()
}
