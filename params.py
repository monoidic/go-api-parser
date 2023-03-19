# currently specific to AMD64 (and possibly Linux)

from itertools import chain
import json

from ghidra.program.model.data import Pointer32DataType, SignedDWordDataType, DWordDataType, BooleanDataType, ByteDataType, Complex16DataType
from ghidra.program.model.data import Complex8DataType, Float4DataType, Float8DataType, SignedWordDataType, SignedQWordDataType, SignedByteDataType
from ghidra.program.model.data import WordDataType, QWordDataType, Undefined8DataType, UndefinedDataType, ArrayDataType, Pointer64DataType

with open('out.json') as fd:
    definitions = json.load(fd)

current_arch = 'linux-amd64' # TODO

typemap = definitions['TypeMap']['all']
typemap.update(definitions['TypeMap'][current_arch]

funcmap = definitions['FuncMap']['all']
funcmap.update(definitions['FuncMap'][current_arch]

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

ptr_size = currentProgram.getDefaultPointerSize()
if ptr_size == 8:
    ptr = Pointer64DataType
    int_t = SignedQWordDataType
    uint_t = QWordDataType
else:
    ptr = Pointer32DataType
    int_t = SignedDWordDataType
    uint_t = DWordDataType

string = StructureDataType('go_string', ptr_size * 2)
string.insertAtOffset(0, ptr(), ptr_size, 'ptr', None)
string.insertAtOffset(ptr_size, int_t(), ptr_size, 'len', None)

slice = StructureDataType('go_slice', ptr_size * 3)
slice.insertAtOffset(0, ptr(UndefinedDataType()), ptr_size, 'ptr', None)
slice.insertAtOffset(ptr_size, int_t(), ptr_size, 'len', None)
slice.insertAtOffset(ptr_size*2, int_t(), ptr_size, 'cap', None)

iface = StructureDataType('go_iface', ptr_size * 2)
iface.insertAtOffset(0, ptr(UndefinedDataType()), ptr_size, 'type_ptr', None)
iface.insertAtOffset(ptr_size, int_t(), ptr_size, 'impl_ptr', None)

integer_registers = ['RAX', 'RBX', 'RCX', 'RDI', 'RSI', 'R8', 'R9', 'R10', 'R11']
float_registers = ['XMM{}'.format(i) for i in range(15)]
registers = {
    reg: currentProgram.getRegister(reg)
    for reg in chain(integer_registers, float_registers)
}

type_map = {
    'iface': lambda: iface,
    'bool': BooleanDataType,
    'byte': ByteDataType,
    'complex128': Complex16DataType,
    'complex64': Complex8DataType,
    'float32': Float4DataType,
    'float64': Float8DataType,
    'int': int_t,
    'int16': SignedWordDataType,
    'int32': SignedDWordDataType,
    'int64': SignedQWordDataType,
    'int8': SignedByteDataType,
    'string': lambda: string,
    'uint': uint_t,
    'uint16': WordDataType,
    'uint32': DWordDataType,
    'uint64': QWordDataType,
    'uintptr': uint_t,
    'undefined8': Undefined8DataType,
    'undefined': UndefinedDataType,
    'struct': lambda: ptr(UndefinedDataType()),  # TODO get struct definitions
    'slice': lambda: slice,
    'error': lambda: iface,
    'code': UndefinedDataType, # TODO something better here?
    # probably don't care about the internals of these
    'chan': lambda: ptr(UndefinedDataType()),
    'map': lambda: ptr(UndefinedDataType()),
}

def get_type(s):
    if s.endswith('*'):
        return ptr(get_type(s[:-1]))
    if s.endswith(']'):
        element_s, num = s[:-1].rsplit('[', 1)
        arr_len = int(num)
        element_type = get_type(element_s)
        return ArrayDataType(element_type, arr_len, element_type.getLength())

    return type_map[s]()

def get_definition(name):
    pass

def main():
    pass

main()
