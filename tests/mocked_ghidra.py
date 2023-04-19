from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class MockGhidraDataType:
    size: int

    def __call__(self) -> 'MockGhidraDataType':
        return self

    def __init__(self, size):
        self.size = size

    def __eq__(self, other):
        if isinstance(other, MockGhidraDataType):
            return self.size == other.size
        return False

    def __repr__(self):
        return f"MockGhidraDataType(size={self.size})"

    def getLength(self):
        return self.size

    def isInteger(self):
        return self.size in [1, 2, 4, 8]

    def isFloat(self):
        return False


"""     def getLength(self) -> int:  # noqa: N802
        return self.size """


@dataclass
class MockedGhidraAbstractFloatDataType(MockGhidraDataType):
    pass


Undefined1DataType = MockGhidraDataType(1)


@dataclass
class MockGhidraPointerType(MockGhidraDataType):
    reference_type: MockGhidraDataType = field(default_factory=Undefined1DataType)  # noqa:E501


@dataclass
class MockGhidraStructureMemberType(MockGhidraDataType):
    data_type: MockGhidraDataType
    name: str

    def getDataType(self) -> MockGhidraDataType:  # noqa:N802
        return self.data_type


@dataclass
class MockGhidraStructureType(MockGhidraDataType):
    name: str
    members: list[MockGhidraStructureMemberType] = field(default_factory=list)

    def __init__(self, name: str, size: int) -> None:
        super().__init__(size)
        self.name = name
        self.members: list[MockGhidraStructureMemberType] = []

    def add(self, data_type: MockGhidraDataType, _length: int,
            component_name: str, _comment: Optional[str]) -> None:
        member = MockGhidraStructureMemberType(
            data_type.size,
            data_type,
            component_name,
        )
        self.members.append(member)
        self.size += member.size

    def getDefinedComponents(self) -> list[MockGhidraStructureMemberType]:  # noqa:N802,E501
        return self.members


@dataclass
class MockGhidraRegister:
    name: str
    size: int
    children_map: dict[str, 'MockGhidraRegister'] = field(repr=False)
    TYPE_VECTOR = 1

    def getChildRegisters(self) -> list['MockGhidraRegister']:  # noqa:N802
        child = self.children_map.get(self.name)
        return [child] if child else []

    def getBitLength(self) -> int:  # noqa:N802
        return self.size * 8

    def getTypeFlags(self) -> int:  # noqa:N802
        return self.TYPE_VECTOR if self.name.startswith('XMM') else 0


_void = object()


@dataclass
class VariableStorage:
    storage: tuple[Any, ...]
    VOID_STORAGE = _void

    def __init__(self, _program: None, *args: Any):
        self.storage = args


@dataclass
class MockGhidraVoidDatatype:
    def __call__(self) -> 'MockGhidraVoidDatatype':
        return self


@dataclass
class ParameterImpl:
    name: str
    datatype: MockGhidraDataType
    storage: VariableStorage
    _program: None = field(repr=False, default=None)


@dataclass
class MockGhidraArrayDataType:
    data_type: MockGhidraDataType
    array_length: int
    element_length: int

    def getLength(self) -> int:
        return self.array_length * self.element_length
