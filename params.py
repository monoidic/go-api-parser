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

# The file 'out.json' which contains function signatures is loaded
# The file is expected to be in the same directory as this script file
filename = os.path.dirname(__file__) + '/out.json'
with open(filename) as fd:
    definitions = json.load(fd)

# Architecture-specific code follows
# As of now, only windows-amd64 is supported. Support for other architectures
# can be added in the future.
current_arch = 'windows-amd64'  # The current architecture

# Function signatures that apply to all architectures are retrieved,
# along with those that are specific to the current architecture.
# This information is stored in the prog_definitions dictionary.
prog_definitions = definitions['all']
for tag in set((
    'cgo', 'amd64', 'windows', 'windows-amd64',
    'windows-cgo', 'windows-amd64-cgo',
)) & set(definitions):
    new_definitions = definitions[tag]
    for key in ('Aliases', 'Funcs', 'Interfaces', 'Structs', 'Types'):
        prog_definitions[key].update(new_definitions[key])

# Determine the size of pointers, and the data type of int and uint.
# This will be different depending on whether the system is 32-bit or 64-bit.
ptr_size = currentProgram.getDefaultPointerSize()
if ptr_size == 8:
    ptr = data.Pointer64DataType
    int_t = data.SignedQWordDataType
    uint_t = data.QWordDataType
else:
    ptr = data.Pointer32DataType
    int_t = data.SignedDWordDataType
    uint_t = data.DWordDataType

# Structs are created for non-trivial built-in types.

# The 'go_string' struct is created, which is similar to a slice, containing a data pointer and length, but without any capacity.
go_string = data.StructureDataType('go_string', 0)
go_string.add(ptr(), ptr_size, 'ptr', None)
go_string.add(int_t(), ptr_size, 'len', None)

# The 'go_slice' struct is created, according to the slice introduction on the Go blog (https://go.dev/blog/slices-intro).
go_slice = data.StructureDataType('go_slice', 0)
go_slice.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)
go_slice.add(int_t(), ptr_size, 'len', None)
go_slice.add(int_t(), ptr_size, 'cap', None)

# The 'go_iface' struct is created, as described in the Go ABI internal memory layout (https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md#memory-layout).
go_iface = data.StructureDataType('go_iface', 0)
go_iface.add(ptr(data.Undefined1DataType()), ptr_size, 'type_ptr', None)
go_iface.add(ptr(data.Undefined1DataType()), ptr_size, 'impl_ptr', None)

# The 'go_chan' struct is created, as mentioned in the Go ABI internal documentation. The internal structure is important as it always consists of a pointer.
go_chan = data.StructureDataType('go_chan', 0)
go_chan.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)

# The 'go_map' struct is created, which is similar to the 'go_chan' struct.
go_map = data.StructureDataType('go_map', 0)
go_map.add(ptr(data.Undefined1DataType()), ptr_size, 'ptr', None)

# The 'go_error' struct is created, which includes a 'go_iface' struct.
go_error = data.StructureDataType('go_error', 0)
go_error.add(go_iface, ptr_size * 2, 'iface', None)

# Additional code for defining various built-in types is provided.
# The code includes definitions for Go strings, Go slices, Go interfaces,
# Go channels, Go maps, and Go errors.

# The language ID of the current program is retrieved. Based on the
# language ID, the integer and float registers are determined.
# Currently, the script supports x86 (with a pointer size of 8) and AARCH64
language_id = currentProgram.getLanguageID().toString()
if language_id.startswith('x86') and ptr_size == 8:
    integer_registers = ['RAX', 'RBX', 'RCX',
                         'RDI', 'RSI', 'R8', 'R9', 'R10', 'R11']
    float_registers = ['XMM{}'.format(i) for i in range(15)]
elif language_id.startswith('AARCH64'):
    integer_registers = ['x{}'.format(i) for i in range(16)]
    float_registers = ['d{}'.format(i) for i in range(16)]
else:
    raise Exception('unhandled platform: {}'.format(language_id))

# Instead of creating a new unique space or using the OTHER_SPACE address space, we are using the address space of the first integer register.
# space = currentProgram.getAddressFactory().getUniqueSpace()
# space = ghidra.program.model.address.AddressSpace.OTHER_SPACE
space = currentProgram.getRegister(integer_registers[0]).getAddressSpace()

# A dictionary named 'regmap' is created. The keys are the register names (strings), such as "RAX", and the values are the corresponding Ghidra register objects.
# The registers are retrieved from the currentProgram.
# Refer to the Ghidra documentation (https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/Register.html) for more information on the Register class.
regmap = {
    reg: currentProgram.getRegister(reg)
    for reg in chain(integer_registers, float_registers)
}

# A mapping from Go type name strings to the corresponding Ghidra data type constructors is created.
# Refer to the Ghidra documentation (https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/package-summary.html) for more information on the data types.
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
    """
    This function is used to create a slice in the Go programming language,
    which is a structure containing a pointer to the data (ptr), length of the data (len),
    and the capacity of the slice (cap). The name of the slice and the data type it
    contains are given as parameters.

    Parameters:
    t (DataType): The data type of the elements that the slice will contain.
    name (str): The name of the slice.

    Returns:
    slice_t (StructureDataType): The constructed slice.

    """
    if name in slices_map:
        return slices_map[name]
    slice_t = data.StructureDataType(name + '[]', 0)
    slice_t.add(ptr(t), ptr_size, 'ptr', None)
    slice_t.add(int_t(), ptr_size, 'len', None)
    slice_t.add(int_t(), ptr_size, 'cap', None)
    return slice_t


# A dictionary used to store and map the types encountered in the program.
type_map = {}


def align(size, align):
    """
    This function finds the first multiple of align greater than or equal to
    the offset given by size, for the purpose of finding start of some element
    which may require padding due to alignment reasons.

    Parameters:
    size (int): An integer offset, in bytes.
    align (int): The alignment required by the element, in bytes.

    Returns:
    int: The offset of the next element.
    """
    return size + (-size % align)


def get_type(s):
    """
    This function retrieves the type of a given string identifier.
    If the identifier is already mapped in type_map, it returns the corresponding type.
    Otherwise, it tries to infer the type based on several possible built-in types,
    pointers, arrays, slices, interfaces, structs, and aliases.

    Parameters:
    s (str): The string identifier for which the type is to be inferred.

    Returns:
    tuple: A tuple containing the inferred type, its length, and alignment.

    Raises:
    Exception: If the type of the string identifier cannot be determined.
    """
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


# A dictionary used to store and map the struct definitions encountered in the program.
struct_defs = {}


def get_struct(name):
    """
    This function retrieves the structure data type corresponding to a given name from the 'struct_defs' dictionary.
    If it does not exist, it creates the data type by examining the corresponding fields in the 'prog_definitions'.
    The created data type includes proper alignment and size calculations.

    Parameters
    ----------
    name : str
        The name of the structure data type.

    Returns
    -------
    tuple
        The tuple consists of:
        - The StructureDataType object,
        - The total size of the structure (considering field sizes and padding for alignment), and
        - The maximum alignment requirement among the fields.

    Note
    ----
    It's important to handle types with circular references carefully to avoid infinite recursion.

    Raises
    ------
    Exception
        Raises an exception if the provided type name is unknown.
    """
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
        # struct_t.growStructure(new_offset - current_offset)
        current_offset = new_offset
        struct_t.insertAtOffset(field_offset, field_t,
                                field_size, field_name, None)

    end_padding = align(current_offset, alignment) - current_offset
    if end_padding:
        struct_t.growStructure(end_padding)

    # required padding byte for non-empty structs
    # struct_t.growStructure(1)
    # struct_t.replaceAtOffset(current_offset, data.ByteDataType(), 1, '_padding_byte', None)
    # current_offset += 1

    res = struct_t, current_offset, alignment
    struct_defs[name] = res
    return res


# for dynamically created struct types; see below
dynamic_type_map = {}


# TODO handle params partially passed on the stack, partially in registers
def get_dynamic_type(types):
    """
    This function retrieves or creates a composite type that combines the
    specified types in the input list. This is used to handle multiple return
    types from Go functions. The generated composite type is stored in the
    `dynamic_type_map` dictionary for reuse.

    Parameters
    ----------
    types : list
        List of type names to be combined into a composite type.

    Returns
    -------
    DataType
        The generated composite type.

    Note
    ----
    The naming convention for the composite type is 'go_dynamic_' followed by
    the input type names joined by '+' symbols.
    """
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
    """
    This function is a generator that yields each defined function within the current binary.
    It provides a simple way to iterate over all the functions in a binary.

    Yields
    ------
    Function
        Each defined function within the current binary in sequence.

    Note
    ----
    The function uses the `getFirstFunction` and `getFunctionAfter` functions from
    Ghidra's API to traverse the list of functions.
    """
    func = getFirstFunction()
    while func is not None:
        yield func
        func = getFunctionAfter(func)


def assign_registers(I, FP, datatype):
    """
    This function attempts to assign registers for a given datatype. Registers are selected based on the
    datatype, either integer or floating point, from a pool of current available registers. It handles padding and
    register overflow scenarios. In the event of an array data type of length more than 1 or if no more registers
    are available, the function fails and returns None.

    Parameters
    ----------
    I : int
        The starting index for the integer register pool.

    FP : int
        The starting index for the floating point register pool.

    datatype : DataType
        The datatype for which to assign registers.

    Returns
    -------
    tuple
        A tuple containing a list of the assigned Varnodes, the last used integer register index,
        and the last used floating point register index.

    Raises
    ------
    Exception
        If a datatype is larger than the current register's length.
    """
    # clone + reverse for .pop() and .append()
    current_int_registers = [regmap[reg]
                             for reg in integer_registers[I:][::-1]]
    current_float_registers = [regmap[reg]
                               for reg in float_registers[FP:][::-1]]
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


def assign_type(type_name, I, FP, stack_offset):
    """
    This function attempts to assign a type either to a register or to the stack. It first attempts to assign
    the type to a register. If assignment to a register fails (for instance, if the type size is too large for
    any available register), the type is assigned to the stack.

    Parameters
    ----------
    type_name : str
        The name of the type to be assigned.

    I : int
        The index of the integer register pool from which to start assignment.

    FP : int
        The index of the floating point register pool from which to start assignment.

    stack_offset : int
        The current offset in the stack, indicating where to start assignment if type is to be placed on the stack.

    Returns
    -------
    tuple
        A tuple containing the following elements:
        - VariableStorage object representing the assignment of the type.
        - The datatype corresponding to the type_name.
        - The final used index from the integer register pool.
        - The final used index from the floating point register pool.
        - The final stack offset after assignment.

    """
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


def get_params(param_types):
    """
    This function processes a list of parameter types and assigns each one to a register or stack.
    It does this by invoking the `assign_type` function on each type in the parameter list.

    Parameters
    ----------
    param_types : list
        The list of parameter types to be assigned. Each type in the list should be represented by
        a dictionary containing at least a 'DataType' key.

    Returns
    -------
    tuple
        A tuple containing the following elements:
        - List of ParameterImpl objects, each representing a parameter and its assigned location.
        - The final stack offset after all assignments.

    """
    result_params = []
    stack_offset = 0
    I = 0
    FP = 0
    # print(param_types)

    for param in param_types:
        storage, datatype, I, FP, stack_offset = assign_type(
            param['DataType'], I, FP, stack_offset)
        # print('storage = {}, datatype = {}, I = {}, FP = {}, stack_offset = {}'.format(storage, datatype, I, FP, stack_offset))

        result_params.append(ParameterImpl(
            param['Name'],
            datatype,
            storage,
            currentProgram,
        ))

    return result_params, stack_offset


def get_results(result_types, stack_offset):
    """
    This function processes a list of result types and assigns each one to a register or stack, similar to `get_params`.
    Since Ghidra only handles a single return value, the function returns a dynamically generated struct type
    with similar storage characteristics when there are multiple return types.

    Parameters
    ----------
    result_types : list
        The list of result types to be assigned. Each type in the list should be represented by a dictionary
        containing at least a 'DataType' key.
    stack_offset : int
        The initial stack offset before assigning the result types.

    Returns
    -------
    tuple
        A tuple containing the following elements:
        - The datatype of the return value. If there are multiple return types, a dynamically generated struct
          type is returned.
        - A VariableStorage instance representing the storage location(s) of the return value(s).
    """
    # special-case for no return type
    if len(result_types) == 0:
        return data.VoidDataType(), VariableStorage.VOID_STORAGE

    I = 0
    FP = 0
    varnodes = []

    if len(result_types) == 1:
        ret_datatype = get_type(result_types[0]['DataType'])[0]
    else:
        ret_datatype = get_dynamic_type(
            [result['DataType'] for result in result_types])

    for param in result_types:
        storage, datatype, I, FP, stack_offset = assign_type(
            param['DataType'], I, FP, stack_offset)
        varnodes.extend(storage.getVarnodes())

    storage = VariableStorage(currentProgram, *varnodes)

    return ret_datatype, storage


def set_storage(func, param_types, result_types):
    """
    This function assigns storage locations to the parameters and results of a given function following certain rules.
    The parameters are assigned first and then the results. Stack offset is updated and aligned after assigning parameters.
    The function storage information is then updated with these assignments.

    Parameters
    ----------
    func : Function
        The function whose storage locations are to be assigned.
    param_types : list
        The list of parameter types to be assigned. Each type in the list should be represented by a dictionary
        containing at least a 'DataType' key.
    result_types : list
        The list of result types to be assigned. Each type in the list should be represented by a dictionary
        containing at least a 'DataType' key.

    Returns
    -------
    None
    """
    # "For each argument A of F, assign A."
    try:
        params, stack_offset = get_params(param_types)
        func.replaceParameters(
            FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED, *params)
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


def recursive_struct_unpack(datatype):
    """
    This function takes in a datatype and recursively unpacks it into its component types.
    It is mainly used to facilitate the assignment of storage locations to composite types
    in registers. For non-composite types, the function simply yields the original type.
    For structures, it recursively yields each component type.

    Parameters
    ----------
    datatype : DataType
        The datatype to be unpacked.

    Yields
    -------
    DataType
        The component types of the input datatype.

    Note
    ----
    For array types of length 0, the function does nothing. For arrays of length 1,
    it recursively register-assigns the one element. For complex types, it recursively
    register-assigns its real and imaginary parts. For integral types that fit into two
    integer registers, it assigns the least significant and most significant halves of
    the value to registers.
    """
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
    """
    This function retrieves the signatures of the functions in a given program and assigns
    storage locations to their parameters and results based on the signatures.

    Note
    ----
    It assumes that `prog_definitions['Funcs']` is a dictionary mapping function names to
    their corresponding signature dictionaries. The function iterates over all the functions
    in the program, retrieves their signatures, and assigns storage locations to the parameters
    and results based on the signature.
    """
    signatures = prog_definitions['Funcs']
    for func in functions_iter():
        signature = signatures.get(func.name)
        if signature:
            print(func.name)
            set_storage(func, signature['Params'], signature['Results'])


main()
