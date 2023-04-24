# currently specific to AMD64 (and possibly Linux)

from itertools import chain
from collections import defaultdict
import json
import os.path

from ghidra.program.model.listing import VariableStorage, ParameterImpl
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.pcode import Varnode

from ghidra.program.model import data

# load file with function signatures
filename = os.path.dirname(__file__) + '/out.json'
with open(filename) as fd:
    definitions = json.load(fd)

# current architecture, for architectures-specific functions
# TODO Ghidra can report platform info, get this dynamically
# once more platforms are supported
current_arch = 'windows-amd64'

# get function signatures applying to all architectures
# + those specific to the current architecture
prog_definitions = definitions['all']
for tag in set((
    'cgo', 'amd64', 'windows', 'windows-amd64',
    'windows-cgo', 'windows-amd64-cgo',
)) & set(definitions):
    new_definitions = definitions[tag]
    for key in ('Aliases', 'Funcs', 'Interfaces', 'Structs', 'Types'):
        prog_definitions[key].update(new_definitions[key])

# set type of int and uint, and type and size of ptr depending on
# whether the system is 32-bit or 64-bit
ptr_size = currentProgram.getDefaultPointerSize()
if ptr_size == 8:
    ptr = data.Pointer64DataType
    int_t = data.SignedQWordDataType
    uint_t = data.QWordDataType
else:
    ptr = data.Pointer32DataType
    int_t = data.SignedDWordDataType
    uint_t = data.DWordDataType

# create structs for non-trivial built-in types

# similar to slice; data pointer and len, but no capacity
go_string = data.StructureDataType('go_string', 0)
go_string.add(ptr(), ptr_size, 'ptr', None)
go_string.add(int_t(), ptr_size, 'len', None)

# https://go.dev/blog/slices-intro
go_slice = data.StructureDataType('go_slice', 0)
go_slice.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)
go_slice.add(int_t(), ptr_size, 'len', None)
go_slice.add(int_t(), ptr_size, 'cap', None)

# mentioned in https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md#memory-layout
go_iface = data.StructureDataType('go_iface', 0)
go_iface.add(ptr(data.Undefined1DataType()), ptr_size, 'type_ptr', None)
go_iface.add(ptr(data.Undefined1DataType()), ptr_size, 'impl_ptr', None)

# mentioned in the above link to always be a pointer; internal structure important
go_chan = data.StructureDataType('go_chan', 0)
go_chan.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)

# same as chan
go_map = data.StructureDataType('go_map', 0)
go_map.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)

go_error = data.StructureDataType('go_error', 0)
go_error.add(go_iface, ptr_size * 2, 'iface', None)

# architecture-specific; TODO select based on architecture
# https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md
language_id = currentProgram.getLanguageID().toString()
if language_id.startswith('x86') and ptr_size == 8:
    integer_registers = ['RAX', 'RBX', 'RCX', 'RDI', 'RSI', 'R8', 'R9', 'R10', 'R11']
    float_registers = ['XMM{}'.format(i) for i in range(15)]
elif language_id.startswith('AARCH64'):
    integer_registers = ['x{}'.format(i) for i in range(16)]
    float_registers = ['d{}'.format(i) for i in range(16)]
else:
    raise Exception('unhandled platform: {}'.format(language_id))

#space = currentProgram.getAddressFactory().getUniqueSpace()
#space = ghidra.program.model.address.AddressSpace.OTHER_SPACE
space = currentProgram.getRegister(integer_registers[0]).getAddressSpace()

# map name string, e.g "RAX", to Ghidra register object corresponding to the register
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/Register.html
regmap = {
    reg: currentProgram.getRegister(reg)
    for reg in chain(integer_registers, float_registers)
}

# map Go type name strings to constructors matching said types in Ghidra
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/package-summary.html
builtins_map = {
    'iface': lambda: go_iface,
    'bool': data.BooleanDataType,
    'byte': data.ByteDataType,
    'rune': data.SignedDWordDataType,
    'complex128': data.Complex16DataType,
    'complex64': data.Complex8DataType,
    'float32': data.Float4DataType,
    'float64': data.Float8DataType,
    'int': int_t,
    'int16': data.SignedWordDataType,
    'int32': data.SignedDWordDataType,
    'int64': data.SignedQWordDataType,
    'int8': data.SignedByteDataType,
    'string': lambda: go_string,
    'uint': uint_t,
    'uint16': data.WordDataType,
    'uint32': data.DWordDataType,
    'uint64': data.QWordDataType,
    'uint8': data.ByteDataType,
    'uintptr': uint_t,
    'unsafe.Pointer': lambda: ptr(data.Undefined1DataType()),
    'undefined8': data.Undefined8DataType,
    'undefined': data.Undefined1DataType,
    'error': lambda: go_error,
    'code': data.Undefined1DataType,  # TODO something better here?
    # probably don't care about the internals of these
    'chan': lambda: go_chan,
    'map': lambda: go_map,
}

align_map = defaultdict(lambda: ptr_size, {
    'bool': 1,
    'uint8': 1,
    'int8': 1,
    'byte': 1,
    'uint16': 2,
    'int16': 2,
    'uint32': 4,
    'int32': 4,
    'rune': 4,
    'float32': 4,
    'complex64': 4,
})

slices_map = {}


def make_slice(t, name):
    if name in slices_map:
        return slices_map[name]
    slice_t = data.StructureDataType(name + '[]', 0)
    slice_t.add(ptr(t), ptr_size, 'ptr', None)
    slice_t.add(int_t(), ptr_size, 'len', None)
    slice_t.add(int_t(), ptr_size, 'cap', None)
    return slice_t


type_map = {}

# align size to be a multiple of align
def align(size, align):
    return size + (-size % align)


def get_type(s):
    if s in type_map:
        return type_map[s]

    if s in builtins_map:
        t = builtins_map[s]()
        ret = t, t.getLength(), align_map[s]
    elif s.endswith('*'):  # pointer
        ret = ptr(get_type(s[:-1])[0]), ptr_size, ptr_size
    elif s.endswith(']'):  # array
        element_s, num = s[:-1].rsplit('[', 1)
        el_type, el_len, el_align = get_type(element_s)
        if num:  # array
            arr_len = int(num)
            aligned_el_len = align(el_len, el_align)
            arr_t = data.ArrayDataType(el_type, arr_len, aligned_el_len)
            ret = arr_t, arr_len * aligned_el_len, el_align
        else:  # slice
            ret = make_slice(el_type, element_s), 3 * ptr_size, ptr_size
    elif s in prog_definitions['Interfaces']:
        ret = go_iface, 2 * ptr_size, ptr_size
    elif s in prog_definitions['Structs']:
        ret = get_struct(s)
    elif s in prog_definitions['Types']:
        ret = get_type(prog_definitions['Types'][s]['Underlying'])
    elif s in prog_definitions['Aliases']:
        ret = get_type(prog_definitions['Aliases'][s]['Target'])
    else:
        raise Exception('unknown type {}'.format(s))

    type_map[s] = ret
    return ret


struct_defs = {}


# TODO ensure it works with types with looping references
def get_struct(name):
    if name in struct_defs:
        return struct_defs[name]

    struct_t = data.StructureDataType(name, 0)
    struct_defs[name] = struct_t, 'x', 'y'

    fields = [
        (get_type(field['DataType']), field['Name'])
        for field in prog_definitions['Structs'][name]['Fields']
    ]

    if not fields:
        res = struct_t, 0, 1
        struct_defs[name] = res
        return res

    current_offset = 0
    alignment = max(field[0][2] for field in fields)

    for ((field_t, field_size, field_align), field_name) in fields:
        if not field_size:
            continue
        field_offset = align(current_offset, field_align)
        new_offset = field_offset + field_size
        #struct_t.growStructure(new_offset - current_offset)
        current_offset = new_offset
        struct_t.insertAtOffset(field_offset, field_t, field_size, field_name, None)

    end_padding = align(current_offset, alignment) - current_offset
    if end_padding:
        struct_t.growStructure(end_padding)

    # required padding byte for non-empty structs
    #struct_t.growStructure(1)
    #struct_t.replaceAtOffset(current_offset, data.ByteDataType(), 1, '_padding_byte', None)
    #current_offset += 1

    res = struct_t, current_offset, alignment
    struct_defs[name] = res
    return res


# for dynamically created struct types; see below
dynamic_type_map = {}


# Ghidra expects functions to only return a single value, however,
# Go allows multiple types to be returned. To facilitate this,
# struct types are generated, which would be assigned in the same way
# in registers or on the stack
# TODO handle params partially passed on the stack, partially in registers
def get_dynamic_type(types):
    name = 'go_dynamic_' + '+'.join(types)
    if name in dynamic_type_map:
        return dynamic_type_map[name]

    t = data.StructureDataType(name, 0)
    for i, typename in enumerate(types):
        el_type, el_size, _el_align = get_type(typename)
        el_name = 'elem_{}_{}'.format(i + 1, typename)
        t.add(el_type, el_size, el_name, None)

    dynamic_type_map[name] = t
    return t

# simplify iterating over functions
# generator that yields each defined function within the currenct binary
def functions_iter():
    func = getFirstFunction()
    while func is not None:
        yield func
        func = getFunctionAfter(func)


# attempts to assign each data type given in the iterable `types`
# (for handling composite types like structs) into registers
# if all given types do not fit into registers, returns None,
# otherwise returns a list of the used registers for the given datatype
# 
# TODO add dummy storage here so struct padding doesn't make
# storage size checks fail
def assign_registers(I, FP, datatype):
    # clone + reverse for .pop() and .append()
    current_int_registers = [regmap[reg] for reg in integer_registers[I:][::-1]]
    current_float_registers = [regmap[reg] for reg in float_registers[FP:][::-1]]
    padding_size = 0
    out = []

    for t in recursive_struct_unpack(datatype):
        if isinstance(t, data.DefaultDataType):
            padding_size += 1
            continue
        if isinstance(t, data.ArrayDataType):
            # "If T is an array type of length > 1, fail."
            return None
        if isinstance(t, data.AbstractFloatDataType):
            registers = current_float_registers
        else:
            registers = current_int_registers

        if len(registers) == 0:
            return None
        t_len = t.getLength()

        while True:
            reg = registers.pop()
            reg_len = reg.getBitLength() >> 3
            if reg_len < t_len:
                raise Exception(t)
            if reg_len == t_len:  # fits at least partially into the register
                out.append(Varnode(reg.getAddress(), reg.getBitLength() >> 3))
                if registers is current_int_registers:
                    I += 1
                else:
                    FP += 1
                break
            # register is too big, get smaller-sized "child register"
            registers.append(reg.getChildRegisters()[0])
    # if padding_size > 0:
    #     out.append(Varnode(space.getAddress(0x10000), padding_size))

    return out, I, FP


# assign to registers or stack
def assign_type(type_name, I, FP, stack_offset):
    datatype, el_size, el_align = get_type(type_name)
    if el_size == 0:
        # "If T has zero size, add T to the stack sequence S and return."
        return VariableStorage(currentProgram, stack_offset, 0), datatype, I, FP, stack_offset
    # "Try to register-assign V."
    reg_info = assign_registers(I, FP, datatype)
    if reg_info is None:  # assign to stack
        # "If step 3 failed, [...] add T to the stack sequence S"
        el_offset = align(stack_offset, el_align)
        storage = [el_offset, el_size]
        stack_offset = el_offset + el_size
    else:  # assign to register
        storage, I, FP = reg_info

    return VariableStorage(currentProgram, *storage), datatype, I, FP, stack_offset



# takes a list of strings as argument and attempts to assign
# the types into parameters; returns a list of ParameterImpl values
# with the datatypes and parameter storage if successful, and None
# if it fails
def get_params(param_types):
    result_params = []
    stack_offset = 0
    I = 0
    FP = 0
    # print(param_types)

    for param in param_types:
        storage, datatype, I, FP, stack_offset = assign_type(param['DataType'], I, FP, stack_offset)
        # print('storage = {}, datatype = {}, I = {}, FP = {}, stack_offset = {}'.format(storage, datatype, I, FP, stack_offset))

        result_params.append(ParameterImpl(
            param['Name'],
            datatype,
            storage,
            currentProgram,
        ))

    return result_params, stack_offset


# same as get_params, but for return values; as only a single return value is handled by Ghidra,
# returns a dynamically generated struct type with similar storage characteristics
def get_results(result_types, stack_offset):
    # special-case for no return type
    if len(result_types) == 0:
        return data.VoidDataType(), VariableStorage.VOID_STORAGE

    I = 0
    FP = 0
    varnodes = []

    if len(result_types) == 1:
        ret_datatype = get_type(result_types[0]['DataType'])[0]
    else:
        ret_datatype = get_dynamic_type([result['DataType'] for result in result_types])

    for param in result_types:
        storage, datatype, I, FP, stack_offset = assign_type(param['DataType'], I, FP, stack_offset)
        varnodes.extend(storage.getVarnodes())

    storage = VariableStorage(currentProgram, *varnodes)

    return ret_datatype, storage


# these need to be parsed together, because the stack positioning
# of the parameters affects the stack positioning of the results
def set_storage(func, param_types, result_types):
    # "For each argument A of F, assign A."
    try:
        params, stack_offset = get_params(param_types)
        func.replaceParameters(FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED, *params)
    # "Add a pointer-alignment field to S"
        stack_offset = align(stack_offset, ptr_size)
    except:
        return
    # "For each result R of F, assign R"
    try:
        ret_datatype, ret_storage = get_results(result_types, stack_offset)
        func.setReturn(ret_datatype, ret_storage, SourceType.USER_DEFINED)
    except:
        pass


# recursively unpack types into component types for register assignment
# just yields a single type for a non-composite type,
# and recursively yields each component type of each component type
# for structs
def recursive_struct_unpack(datatype):
    if isinstance(datatype, data.StructureDataType):
        for component in datatype.getComponents():
            # no `yield from` in py2
            for v in recursive_struct_unpack(component.getDataType()):
                yield v
    elif isinstance(datatype, data.ArrayDataType):
        num_elements = datatype.getNumElements()
        # "If T is an array type of length 0, do nothing."
        # "If T is an array type of length 1, recursively register-assign
        # its one element."
        if num_elements >= 2:
            yield datatype
        elif num_elements == 1:
            yield datatype.getDataType()
    # "If T is a complex type, recursively register-assign
    # its real and imaginary parts."
    elif isinstance(datatype, data.AbstractComplexDataType):
        if isinstance(datatype, data.Complex16DataType):
            float_t = data.Float8DataType
        else:
            float_t = data.Float4DataType
        yield float_t()
        yield float_t()
    # "If T is an integral type that fits in two integer registers,
    # assign the least significant and most significant halves of V
    # to registers I and I+1"
    elif ptr_size == 4 and isinstance(datatype, (data.QWordDataType, data.SignedQWordDataType)):
        if isinstance(datatype, data.QWordDataType):
            half_num_t = data.DWordDataType
        else:
            half_num_t = data.SignedDWordDataType
        yield half_num_t()
        yield half_num_t()
    else:
        yield datatype


def main():
    signatures = prog_definitions['Funcs']
    for func in functions_iter():
        signature = signatures.get(func.name)
        if signature:
            print(func.name)
            set_storage(func, signature['Params'], signature['Results'])


main()
