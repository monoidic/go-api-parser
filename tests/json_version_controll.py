import json
import copy


def get_delta(a, b, path=None):
    if path is None:
        path = []

    delta = {}

    for key in b:
        if key not in a:
            delta["->".join(path + [key])] = b[key]
        else:
            if isinstance(b[key], dict):
                sub_delta = get_delta(a[key], b[key], path + [key])
                delta.update(sub_delta)
            elif b[key] != a[key]:
                delta["->".join(path + [key])] = b[key]

    for key in a:
        if key not in b:
            delta["->".join(path + [key])] = "_DELETED_"

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


with open("go1.json") as fd1, open("go1.0.1.json") as fd2:
    v1 = json.load(fd1)
    v2 = json.load(fd2)

v1_copy = copy.deepcopy(v1)
v2_copy = copy.deepcopy(v2)

delta = get_delta(v1, v2)

delta_applied = apply_delta(v1_copy, delta)

if json.dumps(delta_applied, sort_keys=True) == json.dumps(v2_copy, sort_keys=True):
    print("success")
else:
    print("failure")
