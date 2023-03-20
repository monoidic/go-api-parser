package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

// TODO would just parsing the Go source code directly be better...?
// it'd handle a bunch of runtime functions and unexported functions/methods as well,
// plus make potentially extending this for extracting function signatures from known code easier,
// for all that's worth

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func check1[T any](arg1 T, err error) T {
	check(err)
	return arg1
}

type FuncInfo struct {
	Params     []string
	Results    []string
	arch       string
	symbolName string
}

const (
	INTERFACE  = "iface"
	BOOLEAN    = "bool"
	BYTE       = "byte"
	COMPLEX128 = "complex128"
	COMPLEX64  = "complex64"
	FLOAT32    = "float32"
	FLOAT64    = "float64"
	INT        = "int" // same number of bits as host
	INT16      = "int16"
	INT32      = "int32"
	INT64      = "int64"
	INT8       = "int8"
	RUNE       = "rune"
	STRING     = "string"
	UINT       = "uint" // same number of bits as host
	UINT16     = "uint16"
	UINT32     = "uint32"
	UINT64     = "uint64"
	UINT8      = "uint8"
	UINTPTR    = "uintptr"

	UNKNOWN = "undefined8"
	POINTER = "undefined*"
	STRUCT  = "struct"
	CHAN    = "chan"
	MAP     = "map"
	SLICE   = "slice"
	FUNCPTR = "code*"
	ERROR   = "error"
)

// mapping to Ghidra types
// TODO handle int/uint, iface, string
var builtinTypes = map[string]string{
	"bool":       BOOLEAN,
	"byte":       BYTE,
	"complex128": COMPLEX128,
	"complex64":  COMPLEX64,
	"error":      ERROR,
	"float32":    FLOAT32,
	"float64":    FLOAT64,
	"int":        INT,
	"int16":      INT16,
	"int32":      INT32,
	"int64":      INT64,
	"int8":       INT8,
	"rune":       RUNE,
	"string":     STRING,
	"uint":       UINT,
	"uint16":     UINT16,
	"uint32":     UINT32,
	"uint64":     UINT64,
	"uint8":      UINT8,
	"uintptr":    UINTPTR,
	//"interface{}": INTERFACE,
	//"interface": INTERFACE,
	//"any": INTERFACE,
}

type symbolNameMap struct {
	// maps truncated type path to type identifier, e.g ip.Address => struct
	TypeMap map[string]map[string]string
	// full path => function info
	FuncMap map[string]map[string]FuncInfo
}

func doubleLookup(symMap symbolNameMap, arch, s string) (string, bool) {
	arches := []string{arch, "all"}
	return doubleLookupArches(symMap, arches, s)
}

func doubleLookupArches(symMap symbolNameMap, arches []string, s string) (string, bool) {
	baseMap := symMap.TypeMap
	for _, key := range arches {
		if m, ok := baseMap[key]; ok {
			if t, ok := m[s]; ok {
				return t, true
			}
		}
	}
	return "", false
}

func doubleInsert[T, U comparable, V any](m map[T]map[U]V, k1 T, k2 U, v V) {
	var m2 map[U]V
	if m_, ok := m[k1]; ok {
		m2 = m_
	} else {
		m2 = make(map[U]V)
		m[k1] = m2
	}

	if oldV, ok := m2[k2]; ok {
		//panic(fmt.Sprintf("duplicate key %#v", k2))
		fmt.Printf("duplicate key %#v on %#v, before: %#v, now: %#v\n", k2, k1, oldV, v)
	}
	m2[k2] = v
}

func typeToString(pkgName, arch string, fset *token.FileSet, symMap symbolNameMap, field ast.Expr) (string, bool) {
	switch ft := field.(type) {
	case *ast.StructType:
		return STRUCT, true
	case *ast.ChanType:
		return CHAN, true
	case *ast.MapType:
		return MAP, true
	case *ast.Ellipsis:
		return SLICE, true
	case *ast.FuncType:
		return FUNCPTR, true
	case *ast.InterfaceType:
		return INTERFACE, true
	case *ast.Ident:
		s := ft.Name
		if t, ok := builtinTypes[s]; ok {
			return t, true
		}
		splitPkg := strings.Split(pkgName, "/")
		pkgTail := splitPkg[len(splitPkg)-1]
		s = fmt.Sprintf("%s.%s", pkgTail, s)

		arches := []string{arch}
		if arch != "all" {
			arches = append(arches, "all")
		}
		if pkgName == "syscall" { // workaround for e.g syscall.(WaitStatus).Continued
			arches = append(arches, "freebsd-arm64-cgo")
		}
		return doubleLookupArches(symMap, arches, s)
	case *ast.StarExpr:
		if s, final := typeToString(pkgName, arch, fset, symMap, ft.X); final {
			return s + "*", true
		}
		return "", false
	case *ast.SelectorExpr:
		s := fmt.Sprintf("%s.%s", ft.X.(*ast.Ident).Name, ft.Sel.Name)
		return doubleLookup(symMap, arch, s)
	case *ast.ArrayType:
		if ft.Len == nil {
			return SLICE, true
		}
		literal := ft.Len.(*ast.BasicLit)
		if literal.Kind != token.INT {
			ast.Print(fset, literal)
			panic(1)
		}
		if elementType, final := typeToString(pkgName, arch, fset, symMap, ft.Elt); final {
			return fmt.Sprintf("%s[%s]", elementType, literal.Value), true
		}
		return "", false
	default:
		fmt.Println("unhandled AST expression type")
		ast.Print(fset, field)
		panic(nil)
	}
}

func parseFunc(fset *token.FileSet, symMap symbolNameMap, line string) FuncInfo {
	parts := strings.SplitN(line, ", ", 2)
	pkgInfo := parts[0]
	definition := parts[1]

	pkgData := strings.SplitN(pkgInfo, " ", 3)
	pkgName := pkgData[1]
	pkgArch := "all"
	if len(pkgData) == 3 {
		pkgArch = pkgData[2][1 : len(pkgData[2])-1]
	}

	root := check1(parser.ParseFile(fset, "<input>", "package x\n"+definition, parser.AllErrors))
	fdecl := root.Decls[0].(*ast.FuncDecl)
	funcType := fdecl.Type

	var params, results []string

	if funcType.Params != nil {
		params = make([]string, len(funcType.Params.List))
		for i, param := range funcType.Params.List {
			paramS, final := typeToString(pkgName, pkgArch, fset, symMap, param.Type)
			if !final {
				ast.Print(fset, param.Type)
				panic(1)
			}
			params[i] = paramS
		}
	} else {
		params = make([]string, 0)
	}

	if funcType.Results != nil {
		results = make([]string, len(funcType.Results.List))
		for i, result := range funcType.Results.List {
			resultS, final := typeToString(pkgName, pkgArch, fset, symMap, result.Type)
			if !final {
				ast.Print(fset, result.Type)
				panic(1)
			}
			results[i] = resultS
		}
	} else {
		results = make([]string, 0)
	}

	symbolName := fmt.Sprintf("%s.%s", pkgName, fdecl.Name)

	return FuncInfo{
		symbolName: symbolName,
		Params:     params,
		Results:    results,
		arch:       pkgArch,
	}
}

func parseMethod(fset *token.FileSet, symMap symbolNameMap, line string) FuncInfo {
	parts := strings.SplitN(line, ", ", 2)
	pkgInfo := parts[0]
	definition := parts[1]

	pkgData := strings.SplitN(pkgInfo, " ", 3)
	pkgName := pkgData[1]
	pkgArch := "all"
	if len(pkgData) == 3 {
		pkgArch = pkgData[2][1 : len(pkgData[2])-1]
	}

	definitionParts := strings.SplitN(definition, " ", 3)
	definitionParts[0] = "func"
	recvString := definitionParts[1]
	definition = strings.Join(definitionParts, " ")

	root := check1(parser.ParseFile(fset, "<input>", "package x\n"+definition, parser.AllErrors))
	fdecl := root.Decls[0].(*ast.FuncDecl)
	funcType := fdecl.Type
	receiverAST := fdecl.Recv.List[0].Type

	receiver, ok := typeToString(pkgName, pkgArch, fset, symMap, receiverAST)
	if !ok {
		ast.Print(fset, receiverAST)
		fmt.Println(pkgArch, line)
		panic(nil)
	}

	var params, results []string

	if funcType.Params != nil {
		params = make([]string, len(funcType.Params.List)+1)
		params[0] = receiver
		for i, param := range funcType.Params.List {
			paramS, final := typeToString(pkgName, pkgArch, fset, symMap, param.Type)
			if !final {
				panic(nil)
			}
			params[i+1] = paramS
		}
	} else {
		params = []string{receiver}
	}

	if funcType.Results != nil {
		results = make([]string, len(funcType.Results.List))
		for i, result := range funcType.Results.List {
			resultS, final := typeToString(pkgName, pkgArch, fset, symMap, result.Type)
			if !final {
				panic(nil)
			}
			results[i] = resultS
		}
	} else {
		results = make([]string, 0)
	}

	symbolName := fmt.Sprintf("%s.%s.%s", pkgName, recvString, fdecl.Name)

	return FuncInfo{
		symbolName: symbolName,
		Params:     params,
		Results:    results,
		arch:       pkgArch,
	}

}

func parseTypes(fset *token.FileSet, symMap symbolNameMap, lines []string) {
	prevLen := -1
	for prevLen != 0 {
		var unparsed []string
		for _, line := range lines {
			pkgArch, typeIdent, typeReal, success := parseType(fset, symMap, line)
			if !success {
				unparsed = append(unparsed, line)
				continue
			}
			splitSym := strings.Split(typeIdent, "/")
			shortKey := splitSym[len(splitSym)-1]
			doubleInsert(symMap.TypeMap, pkgArch, shortKey, typeReal)
		}
		newLen := len(unparsed)
		if newLen == prevLen {
			panic(fmt.Sprintf("unhandled lines: %#v", unparsed))
		}
		prevLen = newLen
		lines = unparsed
	}
}

func parseType(fset *token.FileSet, symMap symbolNameMap, line string) (string, string, string, bool) {
	parts := strings.SplitN(line, ", ", 2)
	pkgInfo := parts[0]
	definition := parts[1]

	pkgData := strings.SplitN(pkgInfo, " ", 3)
	pkgName := pkgData[1]
	pkgArch := "all"
	if len(pkgData) == 3 {
		pkgArch = pkgData[2][1 : len(pkgData[2])-1]
	}

	if strings.HasSuffix(definition, "struct") || strings.HasSuffix(definition, "interface") {
		definition += "{}"
	}

	root := check1(parser.ParseFile(fset, "<input>", "package x\n"+definition, parser.AllErrors))
	typespec := root.Decls[0].(*ast.GenDecl).Specs[0].(*ast.TypeSpec)
	typeIdent := fmt.Sprintf("%s.%s", pkgName, typespec.Name.Name)
	typeReal, success := typeToString(pkgName, pkgArch, fset, symMap, typespec.Type)

	return pkgArch, typeIdent, typeReal, success
}

func main() {
	fd := check1(os.Open("api.txt"))
	scanner := bufio.NewScanner(fd)
	fset := token.NewFileSet()

	var funcs, types, methods []string

	for scanner.Scan() {
		line := scanner.Text()
		definition := strings.SplitN(line, ", ", 2)[1]
		defType := strings.SplitN(definition, " ", 2)[0]

		switch defType {
		case "func":
			funcs = append(funcs, line)
		case "method":
			methods = append(methods, line)
		case "type":
			types = append(types, line)
		}
	}
	check(fd.Close())

	// arch => key => value
	symMap := symbolNameMap{
		TypeMap: make(map[string]map[string]string),
		FuncMap: make(map[string]map[string]FuncInfo),
	}

	parseTypes(fset, symMap, types)

	for _, line := range funcs {
		info := parseFunc(fset, symMap, line)
		doubleInsert(symMap.FuncMap, info.arch, info.symbolName, info)
	}

	for _, line := range methods {
		info := parseMethod(fset, symMap, line)
		doubleInsert(symMap.FuncMap, info.arch, info.symbolName, info)
	}

	mapData := check1(json.Marshal(symMap))
	check(os.WriteFile("out.json", mapData, 0o644))
}
