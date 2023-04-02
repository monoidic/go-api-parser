package main

import (
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

	"golang.org/x/tools/go/packages"
)

/* TODO parse:
 * type aliases (add to Aliases map) (TODO need separate methods for these? prolly not)
 * types w/ non-struct underlying type (add to Types map w/ underlying type)
 * types w/ struct underlying type (add to Structs map)
 * interfaces (???)
 * methods (parse while parsing structs, add to Funcs map w/ proper name and receiver as arg;
	        ignore interface methods + methods inherited from embedded fields)
 * functions (add to Funcs map)
*/

func getBuildConstraints() map[string]map[string]bool {
	architectures := []string{
		//"darwin-386",
		//"darwin-386-cgo",
		"darwin-amd64",
		"darwin-amd64-cgo",
		"darwin-arm64",
		"darwin-arm64-cgo",
		"freebsd-386",
		"freebsd-386-cgo",
		"freebsd-amd64",
		"freebsd-amd64-cgo",
		"freebsd-arm",
		"freebsd-arm-cgo",
		"freebsd-arm64",
		"freebsd-arm64-cgo",
		"freebsd-riscv64",
		"freebsd-riscv64-cgo",
		"linux-386",
		"linux-386-cgo",
		"linux-amd64",
		"linux-amd64-cgo",
		"linux-arm",
		"linux-arm-cgo",
		"netbsd-386",
		"netbsd-386-cgo",
		"netbsd-amd64",
		"netbsd-amd64-cgo",
		"netbsd-arm",
		"netbsd-arm-cgo",
		"netbsd-arm64",
		"netbsd-arm64-cgo",
		"openbsd-386",
		"openbsd-386-cgo",
		"openbsd-amd64",
		"openbsd-amd64-cgo",
		"windows-386",
		"windows-amd64",
	}

	out := make(map[string]map[string]bool, len(architectures))

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
	out = append(out, fmt.Sprintf("GOOS=%s", split[0]))
	out = append(out, fmt.Sprintf("GOARCH=%s", split[1]))
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
	// map<architectureString, map<filePath, astFile>>
	archMatches := map[string]bool{"all": true}

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
	if len(archMatches) > 1 {
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
	pkg     *types.Package
	Funcs   map[string]funcData
	Types   map[string]typeData
	Structs map[string]structDef
	Aliases map[string]alias
}

func newPkgData(pkg *types.Package) pkgData {
	return pkgData{
		pkg:     pkg,
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
	// assume the maps are equal at first, then check this assumption;
	// first pass checks if they're equal and just returns x if so
	// (maps are not modified after creation)
	// if not equal, create new ANDed map

	if len(x) == len(y) {
		equal := true
		for name, xV := range x {
			if yV, ok := y[name]; !(ok && xV.equals(yV)) {
				equal = false
				break
			}
		}
		if equal {
			return x
		}
	}

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
		pkg.Aliases[obj.Id()] = alias{Target: obj.Type().String()}
		return
	}
	named := obj.Type().(*types.Named)
	// do not handle generic types
	if named.TypeParams() != nil {
		return
	}
	if t, ok := named.Underlying().(*types.Struct); ok {
		parseStruct(obj.Id(), t, pkg)
	}

	if false {
		parseMethods(obj, pkg)
	}
}

// false if method comes from embedded struct field
func selfMethod(objT types.Type, f *types.Func) bool {
	fmt.Println(f)
	fmt.Println(f.Scope())
	scope := f.Scope()
	names := scope.Names()
	if len(names) != 1 {
		panic(objT)
	}
	realT := scope.Lookup(names[0]).(*types.Var).Type()

	return objT == realT
}

func parseMethods(obj *types.TypeName, pgk pkgData) {
	objT := obj.Type()
	methods := types.NewMethodSet(objT)
	numMethods := methods.Len()
	methodNames := make(map[string]bool, numMethods)

	for i := 0; i < numMethods; i++ {
		method := methods.At(i).Obj()
		methodNames[method.Name()] = true
		if !selfMethod(objT, method.(*types.Func)) {
			continue // comes from embedded field
		}
		// TODO
		fmt.Printf("regular method %s\n", method.Name())
	}

	pObjT := types.NewPointer(objT)
	pMethods := types.NewMethodSet(pObjT)
	numPMethods := pMethods.Len()

	for i := 0; i < numPMethods; i++ {
		method := pMethods.At(i).Obj()
		if methodNames[method.Name()] || !selfMethod(pObjT, method.(*types.Func)) {
			continue // already handled or from embedded field
		}
		// TODO
		fmt.Printf("pointer method %s\n", method.Name())
	}

	// TODO
	if types.NewMethodSet(obj.Type()).Len() != types.NewMethodSet(types.NewPointer(obj.Type())).Len() {
		fmt.Println(types.NewMethodSet(obj.Type()))
		fmt.Println(types.NewMethodSet(types.NewPointer(obj.Type())))

		idkF := types.NewMethodSet(obj.Type()).At(0)
		//idkF := types.NewMethodSet(types.NewPointer(obj.Type())).At(0)
		idkF2 := idkF.Obj().(*types.Func)
		scope := idkF2.Scope()
		names := scope.Names()
		if len(names) != 1 {
			panic(scope)
		}
		preT := scope.Lookup(names[0]).(*types.Var).Type()
		var realT types.Type
		if ptrT, ok := preT.(*types.Pointer); ok {
			realT = ptrT.Elem()
		} else {
			realT = preT
		}
		fmt.Println(objT.String()) // os.file
		fmt.Println(realT)         // os.File
		fmt.Println(objT == realT)
		fmt.Println(idkF.Obj().Name()) // close

		panic(obj)
	}
}

func parseStruct(name string, obj *types.Struct, pkg pkgData) {
	numFields := obj.NumFields()
	fields := make([]namedType, numFields)
	for i := 0; i < numFields; i++ {
		field := obj.Field(i)
		fields[i] = namedType{
			Name:     field.Name(),
			DataType: field.Type().String(),
		}
	}
	pkg.Structs[name] = structDef{Fields: fields}
	fmt.Println(name, fields)
}

func walkPrint(ch <-chan string) {
	fset := token.NewFileSet()
	for path := range ch {
		x := check1(parser.ParseDir(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments))

		for _, astPkg := range x {
			if strings.HasSuffix(astPkg.Name, "_test") || astPkg.Name == "builtin" { // || astPkg.Name == "main" {
				continue
			}

			//ast.Print(fset, astPkg)

			if path == "os" {
				pkgMap := filterPkg(astPkg, path)
				var andedPkg pkgData
				andedFirst := true
				for pkgArch, pkg := range pkgMap {
					fmt.Printf("		%s %s\n", path, pkgArch)
					scope := pkg.Types.Scope()
					names := scope.Names()
					fmt.Printf("%#v\n", names)

					pkgD := newPkgData(pkg.Types)
					for _, name := range names {
						switch obj := scope.Lookup(name).(type) {
						case *types.Func:
							fmt.Println(obj)
							parseFunc(obj, pkgD)
						case *types.TypeName:
							fmt.Println(obj)
							parseType(obj, pkgD)
						}
						continue

						obj := scope.Lookup("a")

						fmt.Printf("%s\n", obj)
						//fmt.Printf("%s.%s: ", obj.Pkg().Path(), obj.Name())
						fmt.Println(types.Id(obj.Pkg(), obj.Name()))

						baseType := obj.Type()

						//switch t := baseType.Underlying().(type) {
						switch t := baseType.(type) {
						case *types.Basic:
							fmt.Printf("basic %s\n", t)
						case *types.Struct:
							fmt.Printf("struct %s\n", t)
						case *types.Signature:
							fmt.Printf("%s: func %s\n", obj.Id(), t)
						case *types.Pointer:
							fmt.Printf("ptr %s\n", t)
						case *types.Interface:
							fmt.Printf("iface %s\n", t)
						case *types.Map:
							fmt.Printf("map %s\n", t)
						case *types.Array:
							fmt.Printf("arr %s\n", t)
						case *types.Slice:
							fmt.Printf("slice %s\n", t)
						case *types.Chan:
							fmt.Printf("chan %s\n", t)
						case *types.Named:
							fmt.Printf("named %s\n", t)
						default:
							panic(t)
						}

						//methods := types.NewMethodSet(baseType)
						methods := types.NewMethodSet(types.NewPointer(baseType))
						numMethods := methods.Len()
						for i := 0; i < numMethods; i++ {
							fmt.Printf("method %d: %s\n", i, methods.At(i))
						}
						if numMethods > 0 {
							fmt.Println()
						}

						methods = types.NewMethodSet(baseType)
						numMethods = methods.Len()
						for i := 0; i < numMethods; i++ {
							fmt.Printf("method %d: %s\n", i, methods.At(i))
						}
						if numMethods > 0 {
							fmt.Println()
						}
					}
					if andedFirst {
						andedPkg = pkgD
						andedFirst = false
					} else {
						andedPkg = andedPkg.and(pkgD)
					}
				}
			}
		}
	}
}

func main() {
	//outPath := check1(filepath.Abs("out.json"))
	check(os.Chdir(os.Args[1]))

	ch := make(chan string)

	go walkPrint(ch)
	walkTreeDirs(ch, ".")
	close(ch)
}
