
import json
import copy


def get_delta(a, b, path=None):
    if path is None:
        path = []

    delta = {}

    for key in b:
        if key not in a:
            delta[tuple(path + [key])] = b[key]
        else:
            if isinstance(b[key], dict):
                sub_delta = get_delta(a[key], b[key], path + [key])
                delta.update(sub_delta)
            elif b[key] != a[key]:
                delta[tuple(path + [key])] = b[key]

    return delta


def apply_delta(a, delta):
    for key_path, value in delta.items():
        current = a
        for key in key_path[:-1]:
            current = current[key]
        current[key_path[-1]] = value

    return a


with open('go1.json') as fd1, open('go1.0.1.json') as fd2:
    v1 = json.load(fd1)
    v2 = json.load(fd2)

v1_copy = copy.deepcopy(v1)
v2_copy = copy.deepcopy(v2)

delta = get_delta(v1, v2)

delta_applied = apply_delta(v1_copy, delta)

if json.dumps(delta_applied, sort_keys=True) == json.dumps(v2_copy, sort_keys=True):
    print('success')
else:
    print('failure')
