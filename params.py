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

current_arch = 'linux-amd64'  # TODO

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
    'chan': lambda: ptr(data.Undefined1DataType()),
    'map': lambda: ptr(data.Undefined1DataType()),
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

# TODO
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/VariableStorage.html
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/ParameterImpl.html
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/FunctionDefinitionDataType.html
# https://ghidra.re/ghidra_docs/api/ghidra/app/cmd/function/ApplyFunctionSignatureCmd.html
# VariableStorage from registers
# ParameterImpl from above VariableStorage + datatype
# create FunctionDefinitionDataType with name, populate arguments with setArguments()
# apply return type on FunctionDefinitionDataType via setReturnType
# (TODO!!! also need to semi-dynamically generate return types for multi-valued returns)
# apply signature to function via ApplyFunctionSignatureCmd
#
# nvm FunctionDB.replaceParameters()


def functions_iter():
    func = getFirstFunction()
    while func is not None:
        yield func
        func  = getFunctionAfter(func)


def assign_registers(registers, length):
    registers = registers[:]

    out = []
    while registers:
        reg = registers[0]
        reg_len = reg.getBitLength() >> 3
        if reg_len > length:
            registers[0] = reg.getChildRegisters()[0]
            continue

        out.append(reg)
        registers = registers[1:]
        length -= reg_len
        if not length:
            return out

    return None

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
        datatype_len = datatype.getLength()

        if isinstance(datatype, data.AbstractFloatDataType):
            remaining_registers = remaining_float_registers
        else:
            remaining_registers = remaining_int_registers

        assigned = assign_registers(remaining_registers, datatype_len)
            if assigned is None:
                return None

        remaining_registers[:len(assigned)] = []

        storage = VariableStorage(currentProgram, *assigned)

        result_params.append(ParameterImpl(
            'parameter_{}'.format(len(result_params) + 1),
            datatype,
            storage,
            currentProgram,
        ))

    return result_params


def main():
    for func in functions_iter():
        try:
            name = func.name.encode()
        except UnicodeEncodeError:
            continue
        signature = funcmap.get(name)
        if signature is None:
            continue

        arguments = get_params(signature['Params'])
        if arguments is not None:
            func.replaceParameters(FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED, *arguments)


        # TODO setReturn


main()
