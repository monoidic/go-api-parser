package main

import (
	"go/types"
	"maps"
	"slices"
)

type Set[T comparable] struct {
	m map[T]struct{}
}

func (s Set[T]) Contains(e T) bool {
	_, ok := s.m[e]
	return ok
}

func makeSet[T comparable](arr []T) Set[T] {
	m := make(map[T]struct{})
	for _, e := range arr {
		m[e] = struct{}{}
	}
	return Set[T]{m: m}
}

type stack[T any] struct {
	l []T
}

func (s *stack[T]) pushMultipleRev(l []T) {
	// reverse sorted order, to pop in "the right" order
	slices.Reverse(l)
	s.l = append(s.l, l...)
}

func (s *stack[T]) push(e T) {
	s.l = append(s.l, e)
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

type buildInfo struct {
	arch string
	path string
}

type pkgArch struct {
	pkg  *types.Package
	arch string
}

type pkgDataArch struct {
	pkgD *pkgData
	arch string
}

type namedType struct {
	Name     string
	DataType string
}

type funcData struct {
	Params  []namedType
	Results []namedType
}

type equalsI interface {
	equals(equalsI) bool
}

func (x funcData) equals(yI equalsI) bool {
	y := yI.(funcData)
	return len(x.Params) == len(y.Params) &&
		len(x.Results) == len(y.Results) &&
		slices.Equal(x.Params, y.Params) &&
		slices.Equal(x.Results, y.Results)
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
	return slices.Equal(x.Fields, yI.(structDef).Fields)
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

func (pkgD *pkgData) Clone() *pkgData {
	return &pkgData{
		Funcs:      maps.Clone(pkgD.Funcs),
		Types:      maps.Clone(pkgD.Types),
		Structs:    maps.Clone(pkgD.Structs),
		Aliases:    maps.Clone(pkgD.Aliases),
		Interfaces: maps.Clone(pkgD.Interfaces),
	}
}

func MapAnd[V equalsI](x, y map[string]V) map[string]V {
	out := make(map[string]V)
	if len(x) > len(y) {
		// swap to iterate over shorter map
		// (order is irrelevant here)
		x, y = y, x
	}
	for name, xV := range x {
		if yV, ok := y[name]; ok && xV.equals(yV) {
			out[name] = xV
		}
	}

	return out
}

func MapAndIn[V equalsI](x, y map[string]V) {
	for name, xV := range x {
		if yV, ok := y[name]; !(ok && xV.equals(yV)) {
			delete(x, name)
		}
	}
}

// get pkgData with definitions existing in both pkg And y
func (pkg *pkgData) And(y *pkgData) *pkgData {
	return &pkgData{
		Funcs:      MapAnd(pkg.Funcs, y.Funcs),
		Types:      MapAnd(pkg.Types, y.Types),
		Structs:    MapAnd(pkg.Structs, y.Structs),
		Aliases:    MapAnd(pkg.Aliases, y.Aliases),
		Interfaces: MapAnd(pkg.Interfaces, y.Interfaces),
	}
}

// in-place and
func (pkg *pkgData) AndIn(y *pkgData) {
	MapAndIn(pkg.Funcs, y.Funcs)
	MapAndIn(pkg.Types, y.Types)
	MapAndIn(pkg.Structs, y.Structs)
	MapAndIn(pkg.Aliases, y.Aliases)
	MapAndIn(pkg.Interfaces, y.Interfaces)
}

func MapAndNot[V equalsI](x, y map[string]V) map[string]V {
	out := make(map[string]V)
	for name, xV := range x {
		if yV, ok := y[name]; !(ok && xV.equals(yV)) {
			out[name] = xV
		}
	}

	return out
}

func MapAndNotIn[V equalsI](x, y map[string]V) {
	for name, xV := range x {
		if yV, ok := y[name]; ok && xV.equals(yV) {
			delete(x, name)
		}
	}
}

// return map with key-value pairs from pkg that do not have an equal pair in y
func (pkg *pkgData) AndNot(y *pkgData) *pkgData {
	return &pkgData{
		Funcs:      MapAndNot(pkg.Funcs, y.Funcs),
		Types:      MapAndNot(pkg.Types, y.Types),
		Structs:    MapAndNot(pkg.Structs, y.Structs),
		Aliases:    MapAndNot(pkg.Aliases, y.Aliases),
		Interfaces: MapAndNot(pkg.Interfaces, y.Interfaces),
	}
}

// in-place version of andNot
func (pkg *pkgData) AndNotIn(y *pkgData) {
	MapAndNotIn(pkg.Funcs, y.Funcs)
	MapAndNotIn(pkg.Types, y.Types)
	MapAndNotIn(pkg.Structs, y.Structs)
	MapAndNotIn(pkg.Aliases, y.Aliases)
	MapAndNotIn(pkg.Interfaces, y.Interfaces)
}

func MapMerge[T any](x, y map[string]T) map[string]T {
	out := maps.Clone(x)
	maps.Copy(out, y)
	return out
}

// return merged map with both x and y
func (pkg *pkgData) Merge(y *pkgData) *pkgData {
	return &pkgData{
		Funcs:      MapMerge(pkg.Funcs, y.Funcs),
		Types:      MapMerge(pkg.Types, y.Types),
		Structs:    MapMerge(pkg.Structs, y.Structs),
		Aliases:    MapMerge(pkg.Aliases, y.Aliases),
		Interfaces: MapMerge(pkg.Interfaces, y.Interfaces),
	}
}

// in-place version of merge
func (pkg *pkgData) MergeIn(y *pkgData) {
	maps.Copy(pkg.Funcs, y.Funcs)
	maps.Copy(pkg.Types, y.Types)
	maps.Copy(pkg.Structs, y.Structs)
	maps.Copy(pkg.Aliases, y.Aliases)
	maps.Copy(pkg.Interfaces, y.Interfaces)
}

func mapNot[T any](x, y map[string]T) map[string]T {
	out := make(map[string]T)
	for k, v := range x {
		if _, ok := y[k]; !ok {
			out[k] = v
		}
	}

	return out
}

func mapNotIn[T any](x, y map[string]T) {
	for k := range y {
		delete(x, k)
	}
}

// remove keys existing in y from pkg
func (pkg *pkgData) Not(y *pkgData) *pkgData {
	return &pkgData{
		Funcs:      mapNot(pkg.Funcs, y.Funcs),
		Types:      mapNot(pkg.Types, y.Types),
		Structs:    mapNot(pkg.Structs, y.Structs),
		Aliases:    mapNot(pkg.Aliases, y.Aliases),
		Interfaces: mapNot(pkg.Interfaces, y.Interfaces),
	}
}

func (pkg *pkgData) NotIn(y *pkgData) {
	mapNotIn(pkg.Funcs, y.Funcs)
	mapNotIn(pkg.Types, y.Types)
	mapNotIn(pkg.Structs, y.Structs)
	mapNotIn(pkg.Aliases, y.Aliases)
	mapNotIn(pkg.Interfaces, y.Interfaces)
}

func (pkg *pkgData) empty() bool {
	return (len(pkg.Funcs) + len(pkg.Types) + len(pkg.Structs) + len(pkg.Aliases) + len(pkg.Interfaces)) == 0
}
