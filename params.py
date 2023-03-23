# currently specific to AMD64 (and possibly Linux)

from itertools import chain
import json
import os.path

from ghidra.program.model.listing import VariableStorage, ParameterImpl
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing.Function import FunctionUpdateType

from ghidra.program.model import data

filename = os.path.dirname(__file__) + '/out.json'
with open(filename) as fd:
    definitions = json.load(fd)

current_arch = 'windows-amd64'  # TODO

typemap = definitions['TypeMap']['all']
typemap.update(definitions['TypeMap'][current_arch])

funcmap = definitions['FuncMap']['all']
funcmap.update(definitions['FuncMap'][current_arch])

ptr_size = currentProgram.getDefaultPointerSize()
if ptr_size == 8:
    ptr = data.Pointer64DataType
    int_t = data.SignedQWordDataType
    uint_t = data.QWordDataType
else:
    ptr = data.Pointer32DataType
    int_t = data.SignedDWordDataType
    uint_t = data.DWordDataType

string = data.StructureDataType('go_string', 0)
string.add(ptr(), ptr_size, 'ptr', None)
string.add(int_t(), ptr_size, 'len', None)

slice = data.StructureDataType('go_slice', 0)
slice.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)
slice.add(int_t(), ptr_size, 'len', None)
slice.add(int_t(), ptr_size, 'cap', None)

iface = data.StructureDataType('go_iface', 0)
iface.add(ptr(data.Undefined1DataType()), ptr_size, 'type_ptr', None)
iface.add(ptr(data.Undefined1DataType()), ptr_size, 'impl_ptr', None)

chan = data.StructureDataType('go_chan', 0)
chan.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)

map = data.StructureDataType('go_map', 0)
map.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)

integer_registers = ['RAX', 'RBX', 'RCX', 'RDI', 'RSI', 'R8', 'R9', 'R10', 'R11']
float_registers = ['XMM{}'.format(i) for i in range(15)]
registers = {
    reg: currentProgram.getRegister(reg)
    for reg in chain(integer_registers, float_registers)
}

type_map = {
    'iface': lambda: iface,
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
    'string': lambda: string,
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
    'slice': lambda: slice,
    'error': lambda: iface,
    'code': data.Undefined1DataType,  # TODO something better here?
    # probably don't care about the internals of these
    'chan': lambda: chan,
    'map': lambda: map,
}


def get_type(s):
    if s.endswith('*'):
        return ptr(get_type(s[:-1]))
    if s.endswith(']'):
        element_s, num = s[:-1].rsplit('[', 1)
        arr_len = int(num)
        element_type = get_type(element_s)
        return data.ArrayDataType(element_type, arr_len, element_type.getLength())

    return type_map[s]()


dynamic_type_map = {}


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

def functions_iter():
    func = getFirstFunction()
    while func is not None:
        yield func
        func = getFunctionAfter(func)


def assign_registers(int_registers, float_registers, types):
    int_registers = int_registers[::-1]
    float_registers = float_registers[::-1]
    out = []

    for t in types:
        t_len = t.getLength()
        while t_len:
            if isinstance(t, data.AbstractFloatDataType):
                registers = float_registers
            else:
                registers = int_registers

            if len(registers) == 0:
                return None

            reg = registers.pop()
            reg_len = reg.getBitLength() >> 3
            if reg_len <= t_len:
                out.append(reg)
                t_len -= reg_len
            else:
                registers.append(reg.getChildRegisters()[0])

    return out


def get_params(param_types):
    if 'struct' in param_types:
        return None

    remaining_int_registers, remaining_float_registers = (
        [registers[name] for name in reglist]
        for reglist in (integer_registers, float_registers)
    )

    result_params = []

    for param in param_types:
        datatype = get_type(param)

        types = recursive_struct_unpack(datatype)

        assigned = assign_registers(remaining_int_registers, remaining_float_registers, types)
        if assigned is None:
            return None

        # TODO amd64-specific
        float_reg_num = sum(1 for reg in assigned if reg.getTypeFlags() & reg.TYPE_VECTOR)
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


def get_results(result_types):
    if 'struct' in result_types:
        return None

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
    assigned = assign_registers(remaining_int_registers, remaining_float_registers, types)
    if assigned is None:
        return None

    storage = VariableStorage(currentProgram, *assigned)

    return datatype, storage


def recursive_struct_unpack(datatype):
    if not isinstance(datatype, data.StructureDataType):
        yield datatype
        return

    for component in datatype.getDefinedComponents():
        # no yield from in py2
        for v in recursive_struct_unpack(component.getDataType()):
            yield v


def main():
    for func in functions_iter():
        signature = funcmap.get(func.name)
        if signature is None:
            continue

        arguments = get_params(signature['Params'])
        if arguments is not None:
            func.replaceParameters(FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED, *arguments)

        results = get_results(signature['Results'])
        if results is not None:
            datatype, storage = results
            func.setReturn(datatype, storage, SourceType.USER_DEFINED)


main()
