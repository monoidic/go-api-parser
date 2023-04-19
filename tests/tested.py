from itertools import chain

import data

from mocked_ghidra import MockGhidraRegister, VariableStorage, ParameterImpl

# start of setup
ptr = data.Pointer64DataType
int_t = data.SignedQWordDataType
uint_t = data.QWordDataType
ptr_size = 64

go_string = data.MockGhidraStructureType('go_string', 0)
go_string.add(ptr(), ptr_size, 'ptr', None)
go_string.add(int_t(), ptr_size, 'len', None)

# mentioned in https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md#memory-layout
go_iface = data.StructureDataType('go_iface', 0)
go_iface.add(ptr(data.Undefined1DataType()), ptr_size, 'type_ptr', None)
go_iface.add(ptr(data.Undefined1DataType()), ptr_size, 'impl_ptr', None)

go_slice = data.StructureDataType('go_slice', 0)
go_slice.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)
go_slice.add(int_t(), ptr_size, 'len', None)
go_slice.add(int_t(), ptr_size, 'cap', None)

go_chan = data.StructureDataType('go_chan', 0)
go_chan.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)

go_map = data.StructureDataType('go_map', 0)
go_map.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)

# map Go type name strings to constructors matching said types in Ghidra
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/package-summary.html
type_map = {
    'iface': lambda: go_iface,
    'bool': data.BooleanDataType,
    'byte': data.ByteDataType,
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
    'undefined8': data.Undefined8DataType,
    'undefined': data.Undefined1DataType,
    # TODO get struct definitions
    'struct': data.Undefined1DataType,
    'slice': lambda: go_slice,
    'error': lambda: go_iface,
    'code': data.Undefined1DataType,  # TODO something better here?
    # probably don't care about the internals of these
    'chan': lambda: go_chan,
    'map': lambda: go_map,
}


integer_registers = [
    'RAX', 'RBX', 'RCX', 'RDI', 'RSI',
    'R8', 'R9', 'R10', 'R11',
]
float_registers = ['XMM{}'.format(i) for i in range(15)]

registers = {}
children_map: dict[str, MockGhidraRegister] = {}


def is_floating_point_type(t):
    if t.size in (4, 8) and t.name != 'complex64' and t.name != 'complex128':
        return True
    return False


def _add_child_reg(parent_name: str, child_name: str, child_size: int) -> None:
    register = MockGhidraRegister(child_name, child_size, children_map)
    children_map[parent_name] = register
    registers[child_name] = register


for name in integer_registers[:5]:
    d_name = name.replace('R', 'E')
    w_name = d_name.replace('E', '')
    b_name = w_name.replace('X', '') + 'L'
    registers[name] = MockGhidraRegister(name, 8, children_map)
    _add_child_reg(name, d_name, 4)
    _add_child_reg(d_name, w_name, 2)
    _add_child_reg(w_name, b_name, 1)

for name in integer_registers[5:]:
    d_name = name + 'D'
    w_name = name + 'W'
    b_name = name + 'B'
    registers[name] = MockGhidraRegister(name, 8, children_map)
    _add_child_reg(name, d_name, 4)
    _add_child_reg(d_name, w_name, 2)
    _add_child_reg(w_name, b_name, 1)


for name in float_registers:
    q_name = name + 'Qa'
    d_name = name + 'Da'
    w_name = name + 'Wa'
    b_name = name + 'Ba'
    registers[name] = MockGhidraRegister(name, 16, children_map)
    _add_child_reg(name, q_name, 8)
    _add_child_reg(q_name, d_name, 4)
    _add_child_reg(d_name, w_name, 2)
    _add_child_reg(w_name, b_name, 1)

currentProgram = None  # noqa:N816

# end of setup


# (for handling composite types like structs) into registers
# if all given types do not fit into registers, returns None,
# otherwise returns a list of the used registers for the given datatype
def assign_registers(int_registers, float_registers, types):
    out = []
    for t in types:
        t_len = t.getLength()
        if t.isInteger():
            reg = next(
                (r for r in int_registers if r.getBitLength() >> 3 == t_len), None)
            if reg is not None:
                int_registers.remove(reg)
        elif t.isFloat():
            reg = next(
                (r for r in float_registers if r.getBitLength() >> 3 >= t_len), None)
            if reg is not None:
                float_registers.remove(reg)
        else:
            continue

        out.append(reg)

    return out


""" def assign_registers(int_registers, float_registers, types):
print("int_registers:", int_registers)
print("float_registers:", float_registers)
print("types:", types)
int_registers = int_registers[::-1]
 float_registers = float_registers[::-1]
  out = []

   for t in types:
        t_len = t.getLength()
        while t_len:  # allocate parts of
            print("current type:", t)
            print("type length:", t_len)
            if is_floating_point_type(t):
                registers = float_registers
            else:
                registers = int_registers

            if len(registers) == 0:
                return None

            reg = registers.pop()
            reg_len = reg.getBitLength() >> 3
            print("selected register:", reg)
            print("register length:", reg_len)
            print("output list before appending:", out)
            if reg_len <= t_len:  # fits at least partially into the register
                out.append(reg)
                t_len -= reg_len
            else:  # register is too big, get smaller-sized "child register"
                registers.append(reg.getChildRegisters()[0])
    print("final output list:", out)
    return out
 """

# takes a list of strings as argument and attempts to assign
# the types into parameters; returns a list of ParameterImpl values
# with the datatypes and parameter storage if successful, and None
# if it fails


def get_params(param_types):
    # TODO structs currently unhandled
    print("get_params called with param_types:", param_types)
    if 'struct' in param_types:
        return None

    # keep track of currently used and available registers
    remaining_int_registers, remaining_float_registers = (
        [registers[name] for name in reglist]
        for reglist in (integer_registers, float_registers)
    )

    result_params = []

    for param in param_types:
        datatype = get_type(param)

        types = recursive_struct_unpack(datatype)

        assigned = assign_registers(
            remaining_int_registers, remaining_float_registers, types)
        if assigned is None:
            return None

        # TODO currently amd64-specific, not all platforms may use vector storage for this
        # when fixing, ensure child registers work too, e.g XMM0's child register XMM0Q or RAX's child EAX
        #
        #  count number of integer and float registers used by the assignment and remove from available registers
        float_reg_num = sum(
            1 for reg in assigned if reg.getTypeFlags() & reg.TYPE_VECTOR)
        int_reg_num = len(assigned) - float_reg_num

        remaining_int_registers = remaining_int_registers[int_reg_num:]
        remaining_float_registers = remaining_float_registers[float_reg_num:]

        storage = VariableStorage(currentProgram, *assigned)

        result_params.append(ParameterImpl(
            'parameter_{}'.format(len(result_params) + 1),
            datatype,
            storage,
            currentProgram,
        ))

    return result_params

# same as get_params, but for return values; as only a single return value is handled by Ghidra,
# returns a dynamically generated struct type with similar storage characteristics


def get_results(result_types):
    print("get_results called with result_types:", result_types)
    # TODO structs currently unhandled
    if 'struct' in result_types:
        return None

    # special-case for no return type
    if len(result_types) == 0:
        return data.VoidDataType(), VariableStorage.VOID_STORAGE

    remaining_int_registers, remaining_float_registers = (
        [registers[name] for name in reglist]
        for reglist in (integer_registers, float_registers)
    )

    if len(result_types) == 1:
        datatype = get_type(result_types[0])
    else:
        datatype = get_dynamic_type(result_types)

    types = recursive_struct_unpack(datatype)
    assigned = assign_registers(
        remaining_int_registers, remaining_float_registers, types)
    if assigned is None:
        return None

    storage = VariableStorage(currentProgram, *assigned)

    return datatype, storage


# recursively unpack types into component types
# just yields a single type for a non-composite type,
# and recursively yields each component type of each component type
# for structs
def recursive_struct_unpack(datatype):
    if not isinstance(datatype, data.StructureDataType):
        yield datatype
        return

    for component in datatype.getDefinedComponents():
        # no `yield from` in py2
        for v in recursive_struct_unpack(component.getDataType()):
            yield v


# recursively parses a type string
# expects a base string matching a type listed in the above type_map,
# and potentially a number of pointer or array type suffixes,
# which it will recursively convert into the proper types,
# e.g "int*" on a 32-bit platform into
# a data.Pointer32DataType referencing a data.SignedDWordDataType,
# or a "int[4]*" into a data.Pointer32DataType referencing a data.ArrayDataType
# referencing 4 instances of data.SignedDWordDataType
def get_type(s):
    if s.endswith('*'):  # pointer
        return ptr(get_type(s[:-1]))
    if s.endswith(']'):  # array
        element_s, num = s[:-1].rsplit('[', 1)
        arr_len = int(num)
        element_type = get_type(element_s)
        return data.ArrayDataType(element_type, arr_len, element_type.getLength())

    return type_map[s]()


# for dynamically created struct types; see below
dynamic_type_map = {}


# Ghidra expects functions to only return a single value, however,
# Go allows multiple types to be returned. To facilitate this,
# struct types are generated, which would be assigned in the same way
# in registers or on the stack
# TODO handle params partially passed on the stack, partially in registers
def get_dynamic_type(types):
    name = '_'.join(chain(['go_dynamic'], types))
    if name in dynamic_type_map:
        return dynamic_type_map[name]

    t = data.StructureDataType(name, 0)
    for i, typename in enumerate(types):
        element_type = get_type(typename)
        t.add(element_type, element_type.getLength(), 'elem_{}'.format(i), None)

    dynamic_type_map[name] = t
    return t
