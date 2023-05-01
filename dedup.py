#!/usr/bin/env python3

import json
import glob
import shutil

from typing import Iterable


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


def get_jsons(filenames: Iterable[str]) -> Iterable[tuple[dict, dict]]:
    with open(filenames[0]) as fd:
        old = json.load(fd)

    for filename in filenames[1:]:
        with open(filename) as fd:
            new = json.load(fd)
        yield old, new
        old = new


def main():
    filenames = sorted(
        glob.glob('results/*.json'),
        key=lambda s: [
            int(num)
            for num in s.split('go')[1][:-5].split('.')
        ],
    )

    shutil.copyfile(filenames[0], f'artifacts/{filenames[0].split("/")[1]}')

    for (old, new), name in zip(get_jsons(filenames), filenames[1:]):
        version = name.split('/')[1][:-5]
        print(version, flush=True)
        delta = get_delta(old, new)
        with open(f'artifacts/{version}_delta.json', 'w') as fd:
            json.dump(delta, fd, sort_keys=True)


if __name__ == '__main__':
    main()
