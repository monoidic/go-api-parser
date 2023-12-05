package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/tools/go/types/typeutil"
)

type parseFunc func(fset *token.FileSet, filename string, src []byte) (*ast.File, error)

var parseDiscards map[string]parseFunc

func getParseDiscards() map[string]parseFunc {
	ret := make(map[string]parseFunc, len(architectures))
	for _, arch := range architectures {
		if getCgo {
			ret[arch] = getParseDiscard(arch)
		} else {
			ret[arch] = parseDiscardFuncBody
		}
	}

	return ret
}

func getParseDiscard(arch string) parseFunc {
	if !strings.Contains(arch, "cgo") {
		return parseDiscardFuncBody
	}
	split := strings.Split(arch, "-")
	if len(split) != 3 {
		panic(arch)
	}

	goos := split[0]
	goarch := split[1]

	if goos == "darwin" {
		// not handled
		return parseDiscardFuncBody
	}

	var triplet, cc, cxx, ar string

	switch fmt.Sprintf("%s-%s", goos, goarch) {
	case "linux-386":
		triplet = "i686-linux-gnu"
	case "linux-amd64":
		triplet = "x86_64-linux-gnu"
	case "linux-arm":
		triplet = "arm-linux-gnueabihf"
	case "linux-arm64":
		triplet = "aarch64-linux-gnu"
	case "windows-386":
		cc = "i686-w64-mingw32-gcc-win32"
		cxx = "i686-w64-mingw32-g++-win32"
		ar = "i686-w64-mingw32-ar"
	case "windows-amd64":
		cc = "x86_64-w64-mingw32-gcc-win32"
		cxx = "x86_64-w64-mingw32-c++-win32"
		ar = "x86_64-w64-mingw32-ar"
	}

	if triplet != "" {
		cc = fmt.Sprintf("%s-gcc", triplet)
		cxx = fmt.Sprintf("%s-g++", triplet)
		ar = fmt.Sprintf("%s-ar", triplet)
	}

	env := append(
		os.Environ(),
		fmt.Sprintf("GOOS=%s", goos),
		fmt.Sprintf("GOARCH=%s", goarch),
		fmt.Sprintf("CC=%s", cc),
		fmt.Sprintf("CXX=%s", cxx),
		fmt.Sprintf("AR=%s", ar),
	)

	return func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
		f, err := parser.ParseFile(fset, filename, src, 0)
		if err != nil {
			return nil, err
		}

		for _, pkg := range f.Imports {
			if path := pkg.Path; path != nil && path.Value == "\"C\"" {
				var buf bytes.Buffer
				cmd := exec.Command("go", "tool", "cgo", "-godefs", filename)
				cmd.Env = env
				cmd.Stdout = &buf
				if err = cmd.Run(); err != nil {
					return nil, nil
				}
				src = buf.Bytes()
				f, err = parser.ParseFile(fset, filename, src, 0)
				if err != nil {
					return nil, err
				}
				break
			}
		}

		for _, decl := range f.Decls {
			if funcDecl, ok := decl.(*ast.FuncDecl); ok {
				funcDecl.Body = nil
			}
		}

		return f, nil
	}

}

func parseDiscardFuncBody(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}

	for _, decl := range f.Decls {
		if funcDecl, ok := decl.(*ast.FuncDecl); ok {
			funcDecl.Body = nil
		}
	}

	return f, nil
}

func (pkg *pkgData) parseFunc(obj *types.Func) {
	signature := obj.Type().(*types.Signature)
	// do not handle generic functions
	if signature.TypeParams() != nil {
		return
	}

	name := obj.FullName()

	params := pkg.tupToSlice(signature.Params(), name+"|param")
	results := pkg.tupToSlice(signature.Results(), name+"|result")

	if !permitInvalid {
		for _, sl := range [][]namedType{params, results} {
			for _, nt := range sl {
				if strings.Contains(nt.DataType, "invalid type") {
					return
				}
			}
		}
	}

	pkg.Funcs[name] = funcData{
		Params:  params,
		Results: results,
	}
}

func (pkg *pkgData) parseType(obj *types.TypeName) {
	name := fmt.Sprintf("%s.%s", obj.Pkg().Path(), obj.Name())
	if obj.IsAlias() {
		target := pkg.getTypeName(obj.Type(), name)
		if permitInvalid || !strings.Contains(target, "invalid type") {
			pkg.Aliases[name] = alias{Target: target}
		}
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

	var isInterface bool
	var typeName, typeUnderlying string

	switch t := named.Underlying().(type) {
	case *types.Struct:
		pkg.parseStruct(pkg.getTypeName(obj.Type(), ""), t)
	case *types.Interface:
		isInterface = true
	case *types.Basic:
		typeName = pkg.getTypeName(obj.Type(), "")
		typeUnderlying = pkg.getTypeName(t, "")
	case *types.Pointer:
		doPanic := false
		switch elT := t.Elem().(type) {
		case *types.Struct:
			if elT.NumFields() == 0 {
				// *struct{}
				typeName = name
				typeUnderlying = "byte*"
			} else {
				doPanic = true
			}
		case *types.Basic:
			typeName = name
			typeUnderlying = elT.Name() + "*"
		case *types.Named:
			elTO := elT.Obj()
			typeName = name
			typeUnderlying = fmt.Sprintf("%s.%s*", elTO.Pkg().Path(), elTO.Name())
		default:
			doPanic = true
		}
		if doPanic {
			panic(fmt.Sprintf("pkg %s, type %s", named.Obj().Pkg().Path(), named))
		}
	case *types.Array, *types.Slice, *types.Map, *types.Chan, *types.Signature:
		typeName = name
		typeUnderlying = pkg.getTypeName(t, name)
	default:
		_ = named.Underlying().(*types.Basic)
	}

	if typeName != "" && (permitInvalid || !strings.Contains(typeUnderlying, "invalid type")) {
		pkg.Types[typeName] = typeData{Underlying: typeUnderlying}
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

	if !permitInvalid {
		for _, sl := range [][]namedType{realParams, results} {
			for _, nt := range sl {
				if strings.Contains(nt.DataType, "invalid type") {
					return
				}
			}
		}
	}

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
		dataType := pkg.getTypeName(field.Type(), fieldPath)
		if !permitInvalid && strings.Contains(dataType, "invalid type") {
			return
		}
		fields[i] = namedType{
			Name:     field.Name(),
			DataType: dataType,
		}
	}
	pkg.Structs[name] = structDef{Fields: fields}
}
