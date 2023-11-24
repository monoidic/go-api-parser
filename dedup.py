#!/usr/bin/env python3

import json
import glob
import shutil

from typing import Iterable


def get_delta(a, b, path=()):
    """
    Computes the difference between two dictionaries.

    Args:
        a (dict): The first dictionary to compare.
        b (dict): The second dictionary to compare.
        path (tuple, optional): The initial path for key tracking. Defaults to an empty tuple.

    Returns:
        dict: A dictionary representing the differences between `a` and `b`.
              The keys are paths (formatted as 'key1->key2->key3') to the values that differ.
              The values are the differing values from `b`. If a key exists in `a` but not in `b`,
              the value in the result will be "_DELETED_" to represent a deleted key.

    Note:
        This function is recursive and it can handle nested dictionaries. It does not support 
        comparing other data structures like lists, tuples, sets etc.

    Examples:
        >> a = {'x': 1, 'y': {'a': 10, 'b': 20}}
        >> b = {'x': 2, 'y': {'a': 10, 'b': 30}, 'z': 3}
        >> get_delta(a, b)
        {'x': 2, 'y->b': 30, 'z': 3, 'y->a': '_DELETED_'}
    """
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
    """
    Applies the changes specified in the `delta` dictionary to the `a` dictionary.

    Args:
        a (dict): The original dictionary to modify.
        delta (dict): The changes to apply to the original dictionary. This should be in the same 
                      format as the output of the `get_delta` function. That is, the keys are paths 
                      (formatted as 'key1->key2->key3') to the values that should be changed, and 
                      the values are the new values. If the new value is "_DELETED_", the key at 
                      that path is deleted.

    Returns:
        dict: The dictionary `a` after applying the changes specified in `delta`.

    Note:
        This function modifies the dictionary `a` in-place, but also returns it for convenience.
        Ensure that this side effect is acceptable in your context.

    Examples:
        >> a = {'x': 1, 'y': {'a': 10, 'b': 20}}
        >> delta = {'x': 2, 'y->b': 30, 'y->a': '_DELETED_'}
        >> apply_delta(a, delta)
        {'x': 2, 'y': {'b': 30}}
    """
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
    """
    Generates pairs of dictionaries from JSON files in a sequence of filenames.

    This function loads each JSON file in `filenames`, and yields tuples of two successive JSONs
    as dictionaries. The first item in each tuple is the JSON from the previous file, and the 
    second item is the JSON from the current file.

    Args:
        filenames (Iterable[str]): An iterable of strings representing JSON filenames. The JSON 
                                   files should be in the order that they are to be compared.

    Yields:
        tuple[dict, dict]: A tuple of two successive JSONs as dictionaries. 

    Examples:
        Suppose we have two JSON files, file1.json and file2.json.
        file1.json: {"a": 1, "b": 2}
        file2.json: {"b": 3, "c": 4}

        >> list(get_jsons(["file1.json", "file2.json"]))
        [({"a": 1, "b": 2}, {"b": 3, "c": 4})]

    Note:
        This function assumes that the JSON files exist and are valid JSON.
    """
    with open(filenames[0]) as fd:
        old = json.load(fd)

    for filename in filenames[1:]:
        with open(filename) as fd:
            new = json.load(fd)
        yield old, new
        old = new


def main():
    """
    This function calculates and writes the differences between successive JSON files.

    This function sorts a collection of JSON files, loads pairs of JSONs from successive files,
    calculates the differences between each pair, and writes the differences to a new JSON file.
    The JSON files are assumed to be in the 'results/' directory and the names of the files are
    expected to follow a specific format that includes versioning information.
    The differences are written to new JSON files in the 'artifacts/' directory.

    Note:
        This function assumes the following:
        - All JSON files are in the 'results/' directory.
        - The names of the JSON files contain versioning information that can be sorted in ascending order.
        - The 'artifacts/' directory exists.

    Side Effects:
        This function creates new JSON files in the 'artifacts/' directory. Each new file is named
        using the version information from the respective JSON file and contains the differences
        between that JSON and the previous one in the sorted order.

    Example:
        Suppose we have three JSON files in 'results/': go1.json, go2.json, and go3.json.
        go1.json: {"a": 1, "b": 2}
        go2.json: {"b": 3, "c": 4}
        go3.json: {"c": 5, "d": 6}

        Running this function will create two new JSON files in 'artifacts/': go2_delta.json and go3_delta.json.
        go2_delta.json: {"->b": 3, "->c": 4, "a": "_DELETED_"}
        go3_delta.json: {"->c": 5, "->d": 6, "b": "_DELETED_"}
    """
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
            json.dump(delta, fd, sort_keys=True, separators=(',', ':'))


if __name__ == '__main__':
    main()
