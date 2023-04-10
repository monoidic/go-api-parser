#!/usr/bin/env python3

import json
import re
from functools import partial
import sys

# remove pointer/array/slice suffixes
pattern = re.compile(r'(\*|\[[0-9]*\])*$')
clean = partial(pattern.sub, "")


def main() -> None:
    with open(sys.argv[1]) as fd:
        data = json.load(fd)

    symbols: set[str] = set()
    defined = {
        'bool', 'byte', 'chan', 'code', 'complex128', 'complex64', 'error',
        'float32', 'float64', 'iface', 'map', 'rune', 'string',
        'uintptr', 'unsafe.Pointer',
    }
    defined.update(
        f'{c}int{num}'
        for c in ('', 'u')
        for num in ('', 8, 16, 32, 64)
    )

    for arch_defs in data.values():
        defined.update(
            key
            for section in ('Types', 'Interfaces', 'Structs', 'Aliases')
            for key in arch_defs[section].keys()
        )

        symbols.update(
            clean(elem['DataType'])
            for func in arch_defs['Funcs'].values()
            for key in ('Params', 'Results')
            for elem in func[key]
        )

        symbols.update(
            clean(field['DataType'])
            for struct in arch_defs['Structs'].values()
            for field in struct['Fields']
        )

        symbols.update(
            clean(alias['Target'])
            for alias in arch_defs['Aliases'].values()
        )

    undefined_sym = symbols - defined
    if undefined_sym:
        print('undefined symbols:', undefined_sym)
    else:
        print('no undefined symbols found')


if __name__ == '__main__':
    main()
