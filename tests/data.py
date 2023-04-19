from functools import partial

from mocked_ghidra import MockGhidraDataType, MockGhidraPointerType
from mocked_ghidra import Undefined1DataType as _Undefined1DataType
from mocked_ghidra import MockGhidraStructureType
from mocked_ghidra import MockGhidraVoidDatatype
from mocked_ghidra import MockedGhidraAbstractFloatDataType
from mocked_ghidra import MockGhidraArrayDataType

AbstractFloatDataType = MockedGhidraAbstractFloatDataType
StructureDataType = MockGhidraStructureType
VoidDataType = MockGhidraVoidDatatype
ArrayDataType = MockGhidraArrayDataType

BooleanDataType = MockGhidraDataType(1)
ByteDataType = MockGhidraDataType(1)
SignedByteDataType = MockGhidraDataType(1)

Complex16DataType = MockGhidraDataType(16)
Complex8DataType = MockGhidraDataType(8)

Float4DataType = AbstractFloatDataType(4)
Float8DataType = AbstractFloatDataType(8)

SignedWordDataType = MockGhidraDataType(2)
SignedDWordDataType = MockGhidraDataType(4)
SignedQWordDataType = MockGhidraDataType(8)

WordDataType = MockGhidraDataType(2)
DWordDataType = MockGhidraDataType(4)
QWordDataType = MockGhidraDataType(8)

Undefined8DataType = MockGhidraDataType(8)
Undefined1DataType = _Undefined1DataType

Pointer32DataType = partial(MockGhidraPointerType, 4)
Pointer64DataType = partial(MockGhidraPointerType, 8)