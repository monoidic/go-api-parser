package main

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// TODO would just parsing the Go source code directly be better...?
// it'd handle a bunch of runtime functions and unexported functions/methods as well,
// plus make potentially extending this for extracting function signatures from known code easier,
// for all that's worth

func getBuildConstraints() map[string]map[string]bool {
	out := make(map[string]map[string]bool)

	for _, architecture := range []string{
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
	} {
		archMap := make(map[string]bool)
		for _, tag := range strings.Split(architecture, "-") {
			archMap[tag] = true
		}
		out[architecture] = archMap
	}

	return out
}

var buildConstraints = getBuildConstraints()

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func check1[T any](arg1 T, err error) T {
	check(err)
	return arg1
}

var filteredNames = map[string]bool{
	"testdata": true,
	"vendor":   true,
	"internal": true,
	"arena":    true,
	"cmd":      true,
}

func walkTreeDirs(ch chan<- string, root string) {
	var dirNames []string

	for _, dir := range check1(os.ReadDir(root)) {
		if dir.IsDir() {
			dirName := dir.Name()
			if !filteredNames[dirName] {
				dirNames = append(dirNames, filepath.Join(root, dir.Name()))
			}
		}
	}

	sort.Strings(dirNames)

	for _, path := range dirNames {
		ch <- path
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

// https://groups.google.com/g/golang-nuts/c/tJSUNwyayis
// drop everything below and just move to go/types? what about build constraints?

func getFilenameBuildTags(filePath string) (goos, goarch string) {
	fileName := filepath.Base(filePath)
	fileName = fileName[:len(fileName)-3]             // remove .go
	potentialTags := strings.Split(fileName, "_")[1:] // drop anything before first _
	if len(potentialTags) == 0 {
		return
	}

	// get last two _-seperated elements
	if tagsStart := len(potentialTags) - 2; tagsStart > 0 {
		potentialTags = potentialTags[tagsStart:]
	}

	//*_GOOS
	//*_GOARCH
	//*_GOOS_GOARCH

	last := potentialTags[len(potentialTags)-1]
	if knownOS[last] {
		goos = last
		return
	}
	if knownArch[last] {
		goarch = last
	}
	if len(potentialTags) == 2 {
		first := potentialTags[0]
		if knownOS[first] {
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

func filterPkg(pkg *ast.Package, path string) map[string]*packages.Package {
	// map<architectureString, map<filePath, astFile>>
	archMatches := map[string]bool{"all": true}

	/*
		conf := types.Config{
			//Importer: importer.Default(),
			//Importer: importer.ForCompiler(token.NewFileSet(), "source", nil),
			//Goversion: "go1.20",
			IgnoreFuncBodies: true,
			//FakeImportC: true,
		}
	*/
	conf := packages.Config{
		// probably only need these (TODO check)
		Mode: packages.NeedTypes | packages.NeedDeps | packages.NeedImports,
		/*
			Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
				packages.NeedImports | packages.NeedDeps | packages.NeedExportFile |
				packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo |
				packages.NeedTypesSizes | packages.NeedModule |
				packages.NeedEmbedFiles | packages.NeedEmbedPatterns,
		*/
		Dir: os.Args[1],
		// use ParseFile to discard function bodies?
		// parallel parsing of separate packages in pipeline?
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

func walkPrint(ch <-chan string) {
	fset := token.NewFileSet()
	for path := range ch {
		x := check1(parser.ParseDir(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments))

		for _, pkg := range x {
			if strings.HasSuffix(pkg.Name, "_test") || pkg.Name == "main" || pkg.Name == "builtin" {
				continue
			}

			//ast.Print(fset, pkg)

			if path == "image/gif" {
				fileMap := filterPkg(pkg, path)
				for _, pkg := range fileMap {
					//fmt.Printf("		%s\n", arch)
					scope := pkg.Types.Scope()
					names := scope.Names()
					//fmt.Printf("%#v\n", names)
					for _, name := range names {
						obj := scope.Lookup(name)

						fmt.Printf("%s.%s: ", obj.Pkg().Path(), obj.Name())

						baseType := obj.Type()

						switch t := baseType.Underlying().(type) {
						case *types.Basic:
							fmt.Printf("basic %s\n", t)
						case *types.Struct:
							fmt.Printf("struct %s\n", t)
						case *types.Signature:
							fmt.Printf("%s.%s: ", obj.Pkg().Path(), obj.Name())
							fmt.Printf("func %s\n", t)
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
