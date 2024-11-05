package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"
)

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

	if tp := signature.TypeParams(); tp != nil {
		pkg.GenericFuncs[name] = genericFuncData{
			Params:     params,
			Results:    results,
			TypeParams: getTypeParamArr(tp),
		}
		return
	}

	pkg.Funcs[name] = funcData{
		Params:  params,
		Results: results,
	}
}

func (pkg *pkgData) parseType(obj *types.TypeName) {
	if obj.IsAlias() {
		if aliasT, ok := obj.Type().(*types.Alias); ok {
			pkg.getTypeName(aliasT, "")
		} else {
			aliasName := getTypeName(obj)
			target := pkg.getTypeName(obj.Type(), "")
			pkg.Aliases[aliasName] = alias{Target: target}
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

	name := getTypeName(obj)

	var isInterface bool
	var typeName, typeUnderlying string

	switch t := named.Underlying().(type) {
	case *types.Struct:
		pkg.parseStruct(pkg.getTypeName(obj.Type(), ""), t, named.TypeParams())
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
			typeUnderlying = getTypeName(elTO)
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
	for i := range tupLen {
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
		if obj.Pkg() == nil {
			// universe scope
			return obj.Name()
		}
		// full package path
		return getTypeName(obj)
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
		pkg.parseStruct(name, dt, nil)
		return name
	case *types.Alias:
		obj := dt.Obj()
		aliasName := getTypeName(obj)
		targetName := pkg.getTypeName(types.Unalias(dt), "alias_"+aliasName)
		pkg.Aliases[aliasName] = alias{Target: targetName}
		return aliasName
	case *types.TypeParam:
		return dt.String()
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

func (pkg *pkgData) parseStruct(name string, obj *types.Struct, typeParams *types.TypeParamList) {
	numFields := obj.NumFields()
	fields := make([]namedType, numFields)
	for i := range numFields {
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

	if typeParams != nil {
		pkg.GenericStructs[name] = genericStructDef{
			Fields:     fields,
			TypeParams: getTypeParamArr(typeParams),
		}
		return
	}

	pkg.Structs[name] = structDef{Fields: fields}
}

func getTypeName(tn *types.TypeName) string {
	pkg := tn.Pkg()
	if pkg == nil {
		// universe scope
		return tn.Name()
	}
	return fmt.Sprintf("%s.%s", pkg.Path(), tn.Name())
}

func getTypeParamArr(typeParams *types.TypeParamList) []string {
	tParamsArr := make([]string, typeParams.Len())

	for i := range typeParams.Len() {
		tParamsArr[i] = typeParams.At(i).String()
	}

	return tParamsArr
}
