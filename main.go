package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TODO would just parsing the Go source code directly be better...?
// it'd handle a bunch of runtime functions and unexported functions/methods as well,
// plus make potentially extending this for extracting function signatures from known code easier,
// for all that's worth

func getBuildConstraints() map[string]map[string]bool {
	out := make(map[string]map[string]bool)

	for _, architecture := range []string{
		"darwin-386",
		"darwin-386-cgo",
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

func getImporter(fset *token.FileSet, filter func(fs.FileInfo) bool) ast.Importer {
	return func(imports map[string]*ast.Object, path string) (pkg *ast.Object, err error) {
		if oldPkg, ok := imports[path]; ok {
			return oldPkg, nil
		}

		pathBase := filepath.Base(path)

		pkgMap := check1(parser.ParseDir(fset, path, filter, parser.AllErrors))
		for pkgName, pkg := range pkgMap {
			if pkgName == pathBase {
				obj := &ast.Object{
					Kind: ast.Pkg,
					Name: pkgName,
					Data: pkg.Scope,
				}
				imports[path] = obj
				return obj, nil
			}
		}
		return nil, errors.New("failed import")
	}
}

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

type pkgFset struct {
	pkg  *ast.Package
	fset *token.FileSet
}

func filterPkg(pkg *ast.Package, path string) map[string]pkgFset {
	archFiles := make(map[string]map[string]*ast.File)

	for arch := range buildConstraints {
		archFiles[arch] = make(map[string]*ast.File)
	}
	archFiles["all"] = make(map[string]*ast.File)

	for filePath, fileObj := range pkg.Files {
		if strings.HasSuffix(filePath, "_test.go") {
			continue
		}

		expr := getTags(filePath, fileObj)
		// no build constraints
		if expr == nil {
			archFiles["all"][filePath] = fileObj
			continue
		}

		// identify which tag sets set in buildConstraints match
		for arch, constraints := range buildConstraints {
			if expr.Eval(func(tag string) bool { return constraints[tag] }) {
				archFiles[arch][filePath] = fileObj
			}
		}
	}

	out := make(map[string]pkgFset)

	for arch, fileMap := range archFiles {
		if len(fileMap) == 0 {
			continue
		}

		if arch != "all" {
			for filePath, fileObj := range archFiles["all"] {
				fileMap[filePath] = fileObj
			}
		}

		fset := token.NewFileSet()
		importer := getImporter(fset, nil)

		newFileMap := make(map[string]*ast.File)
		for filePath := range fileMap {
			newFileMap[filePath] = check1(parser.ParseFile(fset, filePath, nil, parser.AllErrors))
		}
		newPkg := check1(ast.NewPackage(fset, newFileMap, importer, &ast.Scope{}))

		out[arch] = pkgFset{pkg: newPkg, fset: fset}
	}

	return out
}

func walkPrint(ch <-chan string) {
	fset := token.NewFileSet()
	for path := range ch {
		x := check1(parser.ParseDir(fset, path, nil, parser.PackageClauseOnly|parser.ParseComments))
		fmt.Println(path)

		for pkgName, pkg := range x {
			if strings.HasSuffix(pkg.Name, "_test") || pkg.Name == "main" {
				continue
			}
			fmt.Printf("	%s\n", pkg.Name)

			//ast.Print(fset, pkg)

			if pkgName == "tar" {
				fileMap := filterPkg(pkg, path)
				for arch, ffset := range fileMap {
					fmt.Printf("		%s\n", arch)
					_ = ffset
					ast.Print(ffset.fset, ffset.pkg)
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
