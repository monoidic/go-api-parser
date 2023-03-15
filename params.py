from ghidra.program.model.data import Pointer32DataType, SignedDWordDataType, DWordDataType, BooleanDataType, ByteDataType, Complex16DataType
from ghidra.program.model.data import Complex8DataType, Float4DataType, Float8DataType, SignedWordDataType, SignedQWordDataType, SignedByteDataType
from ghidra.program.model.data import WordDataType, QWordDataType, Undefined8DataType, UndefinedDataType, ArrayDataType, Pointer64DataType

# TODO map int/uint/ptr here
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
slice.insertAtOffset(0, ptr(), ptr_size, 'ptr', None)
slice.insertAtOffset(ptr_size, int_t(), ptr_size, 'len', None)
slice.insertAtOffset(ptr_size*2, int_t(), ptr_size, 'cap', None)

iface = StructureDataType('go_iface', ptr_size * 2)
slice.insertAtOffset(0, ptr(), ptr_size, 'type_ptr', None)
slice.insertAtOffset(ptr_size, ptr(), ptr_size, 'impl_ptr', None)

type_map = {
    'iface': lambda: iface,
    'bool': BooleanDataType,
    'byte': ByteDataType,
    'complex16': Complex16DataType,
    'complex8': Complex8DataType,
    'float4': Float4DataType,
    'float8': Float8DataType,
    'int': int_t,
    'sword': SignedWordDataType,
    'sdword': SignedDWordDataType,
    'sqword': SignedQWordDataType,
    'sbyte': SignedByteDataType,
    'string': lambda: string,
    'uint': uint_t,
    'word': WordDataType,
    'dword': DWordDataType,
    'qword': QWordDataType,
    'uintptr_t': uint_t,
    'undefined8': Undefined8DataType,
    'undefined': UndefinedDataType,
    'struct': lambda: ptr(UndefinedDataType()),
    'chan': lambda: ptr(UndefinedDataType()),
    'map': lambda: ptr(UndefinedDataType()),
    'slice': lambda: slice,
    'code': UndefinedDataType, # TODO something better here?
    'error': lambda: iface,
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

def main():
    pass

main()
