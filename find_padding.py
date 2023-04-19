#!/usr/bin/env python3

import json
from dataclasses import dataclass
from typing import Any

POINTER_SIZE = 8


class NotFoundError(Exception):
    ...


@dataclass
class GoType:
    size: int
    align: int
    has_padding: bool = False


known: dict[str, GoType] = {
    'complex64': GoType(8, 4),
    'complex128': GoType(16, POINTER_SIZE),
}

for t, names in [
    (GoType(1, 1), ['bool', 'int8', 'uint8', 'byte']),
    (GoType(2, 2), ['int16', 'uint16']),
    (GoType(4, 4), ['int32', 'uint32', 'rune', 'float32']),
    (GoType(8, POINTER_SIZE), ['int64', 'uint64', 'float64']),
    (GoType(POINTER_SIZE, POINTER_SIZE), [
        'int', 'uint', 'unsafe.Pointer', 'uintptr', 'map', 'code', 'chan'
    ]),
    (GoType(POINTER_SIZE * 2, POINTER_SIZE), ['error', 'iface', 'string']),
]:
    for name in names:
        known[name] = t

slice_t = GoType(POINTER_SIZE * 3, POINTER_SIZE)


# round x up to a multiple of y
def align(size: int, align: int) -> int:
    return size + (-size % align)


def get_type(name: str, data: dict[str, Any]) -> GoType:
    if name in known:
        return known[name]

    if name.endswith('*'):
        ret = known['uintptr']
    elif name.endswith('[]'):
        ret = slice_t
    elif name.endswith(']'):
        underlying_name, arr_len_s = name.rsplit('[', 1)
        arr_len = int(arr_len_s[:-1])
        underlying = get_type(underlying_name, data)
        # arrays of elements are padded in the middle
        arr_size = align(underlying.size, underlying.align) * (arr_len - 1)
        arr_size += underlying.size
        ret = GoType(arr_size, underlying.align)
    elif name in data['Interfaces']:
        ret = known['iface']
    elif name in data['Types']:
        ret = get_type(data['Types'][name]['Underlying'], data)
    elif name in data['Structs']:
        ret = get_struct(name, data)
    elif name in data['Aliases']:
        ret = get_type(data['Aliases'][name]['Target'], data)
    else:
        raise NotFoundError(f'unknown name {name}')
    known[name] = ret
    return ret


def get_struct(name: str, data: dict[str, Any]) -> GoType:
    types = [
        get_type(field['DataType'], data)
        for field in data['Structs'][name]['Fields']
    ]
    size = 0

    for t in types:
        size = align(size, t.align) + t.size

    alignment = max((t.align for t in types), default=1)
    # size = align(size, alignment)

    return GoType(
        size=size,
        align=alignment,
        has_padding=size > align(sum(t.size for t in types), alignment),
    )


def main() -> None:
    with open('results/go1.20.3.json', encoding='utf8') as fd:
        data = json.load(fd)['all']

    for name in data['Structs']:
        try:
            go_type = get_type(name, data)
        except NotFoundError:
            continue
        if go_type.has_padding:
            print(name)


if __name__ == '__main__':
    main()
