#!/usr/bin/env python3

import glob
import json

from dedup import apply_delta


def get_version(path: str) -> str:
    return path.split('go')[1][:-5].removesuffix('_delta')


def main() -> None:
    filenames = sorted(
        glob.glob('deduped/*.json'),
        key=lambda s: [
            int(num)
            for num in get_version(s).split('.')
        ],
    )
    base, rest = filenames[0], filenames[1:]
    print(base, rest)

    with open(base) as fd:
        definitions = json.load(fd)

    version = get_version(base)
    with open(f'results/go{version}.json', 'w') as fd:
        json.dump(definitions, fd)

    for path in rest:
        with open(path) as fd:
            delta = json.load(fd)
        apply_delta(definitions, delta)
        version = get_version(path)
        with open(f'results/go{version}.json', 'w') as fd:
            json.dump(definitions, fd)
        print(f'{version} done')


if __name__ == '__main__':
    main()
