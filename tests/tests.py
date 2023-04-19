#!/usr/bin/env python3

import unittest
import data
from mocked_ghidra import MockGhidraRegister, VariableStorage, ParameterImpl

from tested import get_results, get_params, registers, go_chan, go_map, go_string


class TestRegisterOnly(unittest.TestCase):
    def test_empty(self) -> None:
        results = get_results(())
        self.assertIsNotNone(results)
        datatype, storage = results
        self.assertEqual(datatype, data.VoidDataType())
        self.assertEqual(storage, VariableStorage.VOID_STORAGE)

        params = get_params(())
        self.assertIsNotNone(params)
        self.assertEqual(params, [])

    def test_params(self) -> None:
        for param_types, expected in [
            # "If T is a boolean or integral type that fits in
            # an integer register, assign V to register I and increment I."
            (
                ['bool'],
                [
                    ParameterImpl(
                        name='parameter_1',
                        datatype=data.BooleanDataType(),
                        storage=VariableStorage(None, registers['AL']),
                    ),
                ],
            ),
            (
                ['bool', 'int64'],
                [
                    ParameterImpl(
                        name='parameter_1',
                        datatype=data.BooleanDataType(),
                        storage=VariableStorage(None, registers['AL']),
                    ),
                    ParameterImpl(
                        name='parameter_2',
                        datatype=data.SignedQWordDataType(),
                        storage=VariableStorage(None, registers['RBX']),
                    ),
                ],
            ),
            # "If T is a floating-point type and can be represented
            # without loss of precision in a floating-point register, assign V
            # to register FP and increment FP."
            (
                ['complex128'],
                [
                    ParameterImpl(
                        name='parameter_1',
                        datatype=data.Complex16DataType(),
                        storage=VariableStorage(
                            None,
                            registers['XMM0Qa'],
                            registers['XMM1Qa'],
                        ),
                    ),
                ],
            ),
            # "If T is a pointer type, map type, channel type, or
            # function type, assign V to register I and increment I.
            (
                ['struct*', 'map', 'chan', 'code*'],
                [
                    ParameterImpl(
                        name='parameter_1',
                        datatype=data.Pointer64DataType(),
                        storage=VariableStorage(None, registers['RAX']),
                    ),
                    ParameterImpl(
                        name='parameter_2',
                        datatype=go_map,
                        storage=VariableStorage(None, registers['RBX']),
                    ),
                    ParameterImpl(
                        name='parameter_3',
                        datatype=go_chan,
                        storage=VariableStorage(None, registers['RCX']),
                    ),
                    ParameterImpl(
                        name='parameter_4',
                        datatype=data.Pointer64DataType(),
                        storage=VariableStorage(None, registers['RDI']),
                    ),
                ],
            ),
            # "If T is a struct type, recursively register-assign
            # each field of V."
            (
                ['string'],
                [
                    ParameterImpl(
                        name='parameter_1',
                        datatype=go_string,
                        storage=VariableStorage(
                            None,
                            registers['RAX'],
                            registers['RBX'],
                        ),
                    ),
                ],
            ),
            # "If T is an array type of length 0, do nothing."
            (
                ['int[0]'],
                [],
            ),
            # "If T is an array type of length 1, recursively register-assign
            # its one element."
            (
                ['int[1]'],
                [
                    ParameterImpl(
                        name='parameter_1',
                        datatype=data.SignedQWordDataType(),
                        storage=VariableStorage(None, registers['RAX']),
                    )
                ],
            )
        ]:
            params = get_params(param_types)
            self.assertIsNotNone(params)
            self.assertEqual(expected, params)
            print("Expected:")
            print(expected)
            print("Actual:")
            print(params)


if __name__ == '__main__':
    TestRegisterOnly.maxDiff = None
    unittest.main()
