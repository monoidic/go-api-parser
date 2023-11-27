package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/types/typeutil"
)

/* TODO parse:
* more/better dedup groups in archSplit?

* handle type aliased structs, e.g internal/fuzz.CorpusEntry, better,
  instead of creating a bunch of anonymous struct definitions everywhere they appear
  in function signatures or in structs

* get rid of all of those "invalid type"s

*/

// just what's considered to have first-class support (all of these are available after 1.5)
// for line in $(go tool dist list -json | jq -r '.[] | select(.FirstClass == true) | .GOOS + "-" + .GOARCH'); do echo $line; echo ${line}-cgo; done | jq -Rsc 'split("\n") | .[:-1]'
var architectures []string
var architectureSet Set[string]
var buildConstraints map[string]map[string]bool

func check(err error) {
	if err != nil {
		log.Panicln(err)
	}
}

func check1[T any](arg1 T, err error) T {
	check(err)
	return arg1
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
		Dir:       sourceRoot,
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

var (
	sourceRoot    string
	outPath       string
	goVersion     string
	permitInvalid bool
)

func lateInit() {
	architectures = getArchitectures()
	architectureSet = makeSet(architectures)
	buildConstraints = getBuildConstraints()
}

func main() {
	flag.StringVar(&sourceRoot, "src", "", "path to directory with source code to examine")
	flag.StringVar(&outPath, "out", "", "path to file to dump json results in")
	flag.StringVar(&goVersion, "version", runtime.Version(), "go version to use, in go1.${minor}.${patch} format")
	flag.BoolVar(&permitInvalid, "permit_invalid", false, "permit \"invalid type\" results")
	flag.Parse()
	if sourceRoot == "" || outPath == "" {
		flag.PrintDefaults()
		return
	}

	lateInit()

	absOutPath := check1(filepath.Abs(outPath))
	check(os.Chdir(sourceRoot))

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

	pkgMerge(extractedChan, absOutPath)
}
