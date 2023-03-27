#!/usr/bin/env python3

import unittest

import data
from mocked_ghidra import MockGhidraRegister, VariableStorage

from tested import get_results, get_params


class TestRegisterAssign(unittest.TestCase):
    def test_void(self) -> None:
        types = ()
        results = get_results(('bool',))
        print(results)


if __name__ == '__main__':
    unittest.main()
