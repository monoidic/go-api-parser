# easy ver.
from distutils.version import LooseVersion


def sort_go_versions(versions):
    return sorted(versions, key=LooseVersion)


versions = [
    "go1.14",
    "go1.14.6",
    "go1.14.12",
    "go1.15",
    "go1.20",
    "go1.20.5",
    "go1.20.10",
    "go1.20.3",
]

sorted_versions = sort_go_versions(versions)
print(sorted_versions)


# hard version
def go_version_key(version_str):
    parts = version_str[2:].split(".")
    major = int(parts[0])
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    return (major, minor, patch)


def sort_go_versions(versions):
    return sorted(versions, key=go_version_key)


versions = [
    "go1.14",
    "go1.14.6",
    "go1.14.12",
    "go1.15",
    "go1.20",
    "go1.20.5",
    "go1.20.10",
    "go1.20.3",
]

sorted_versions = sort_go_versions(versions)
print(sorted_versions)
