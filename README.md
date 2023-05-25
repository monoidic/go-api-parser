# make_slice

<pre><code>This function is used to create a slice in the Go programming language, 
which is a structure containing a pointer to the data (ptr), length of the data (len),
and the capacity of the slice (cap). The name of the slice and the data type it 
contains are given as parameters.

Parameters:
t (DataType): The data type of the elements that the slice will contain.
name (str): The name of the slice.

Returns:
slice_t (StructureDataType): The constructed slice.
</code></pre>

# align

<pre><code>This function retrieves the type of a given string identifier. 
If the identifier is already mapped in type_map, it returns the corresponding type. 
Otherwise, it tries to infer the type based on several possible built-in types,
pointers, arrays, slices, interfaces, structs, and aliases.

Parameters:
s (str): The string identifier for which the type is to be inferred.

Returns:
tuple: A tuple containing the inferred type, its length, and alignment.

Raises:
Exception: If the type of the string identifier cannot be determined.
</code></pre>

# get_type

<pre><code>This function retrieves the type of a given string identifier. 
If the identifier is already mapped in type_map, it returns the corresponding type. 
Otherwise, it tries to infer the type based on several possible built-in types,
pointers, arrays, slices, interfaces, structs, and aliases.

Parameters:
s (str): The string identifier for which the type is to be inferred.

Returns:
tuple: A tuple containing the inferred type, its length, and alignment.

Raises:
Exception: If the type of the string identifier cannot be determined.
</code></pre>

# get_struct

<pre><code>This function retrieves the structure data type corresponding to a given name from the 'struct_defs' dictionary.
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
</code></pre>

# get_dynamic_type

<pre><code>This function retrieves or creates a composite type that combines the 
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
</code></pre>

# functions_iter

<pre><code>This function is a generator that yields each defined function within the current binary. 
It provides a simple way to iterate over all the functions in a binary.

Yields
------
Function
    Each defined function within the current binary in sequence.

Note
----
The function uses the `getFirstFunction` and `getFunctionAfter` functions from 
Ghidra's API to traverse the list of functions.
</code></pre>

# assign_registers

<pre><code>This function attempts to assign registers for a given datatype. Registers are selected based on the 
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
</code></pre>

# assign_type

<pre><code>This function attempts to assign a type either to a register or to the stack. It first attempts to assign 
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
</code></pre>

# get_params

<pre><code>This function processes a list of parameter types and assigns each one to a register or stack. 
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
</code></pre>

# get_results

<pre><code>This function processes a list of result types and assigns each one to a register or stack, similar to `get_params`. 
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
</code></pre>

# set_storage

<pre><code>This function assigns storage locations to the parameters and results of a given function following certain rules. 
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
</code></pre>

# recursive_struct_unpack

<pre><code>This function takes in a datatype and recursively unpacks it into its component types.
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
</code></pre>

# main

<pre><code>This function retrieves the signatures of the functions in a given program and assigns 
storage locations to their parameters and results based on the signatures.

Note
----
It assumes that `prog_definitions['Funcs']` is a dictionary mapping function names to 
their corresponding signature dictionaries. The function iterates over all the functions 
in the program, retrieves their signatures, and assigns storage locations to the parameters
and results based on the signature.
</code></pre>

