#!/usr/bin/env python3

import json
import glob
import shutil

from typing import Iterable
from itertools import tee


def get_delta(a, b, path=()):
    delta = {}

    for key in b:
        current_path = path + (key,)
        if key not in a:
            delta["->".join(current_path)] = b[key]
        else:
            if isinstance(b[key], dict):
                sub_delta = get_delta(a[key], b[key], current_path)
                delta.update(sub_delta)
            elif b[key] != a[key]:
                delta["->".join(current_path)] = b[key]

    for key in set(a) - set(b):
        delta["->".join(path + (key,))] = "_DELETED_"

    return delta


def apply_delta(a, delta):
    for key_path, value in delta.items():
        key_list = key_path.split("->")
        current = a
        for key in key_list[:-1]:
            current = current[key]

        if value == "_DELETED_":
            del current[key_list[-1]]
        else:
            current[key_list[-1]] = value

    return a


def get_jsons(filenames: Iterable[str]) -> Iterable[dict]:
    for filename in filenames:
        with open(filename) as fd:
            data = json.load(fd)
        yield data


def main():
    filenames = sorted(
        glob.glob('results/*.json'),
        key=lambda s: [
            int(num)
            for num in s.split('go')[1][:-5].split('.')
        ],
    )

    jsons1, jsons2 = tee(get_jsons(filenames))
    next(jsons2)

    shutil.copyfile(filenames[0], f'artifacts/{filenames[0].split("/")[1]}')

    for old, new, name in zip(jsons1, jsons2, filenames[1:]):
        version = name.split('/')[1][:-5]
        print(version)
        delta = get_delta(old, new)
        with open(f'artifacts/{version}_delta.json', 'w') as fd:
            json.dump(delta, fd)


if __name__ == '__main__':
    main()
