from fuzzgen4ghidra_engine.params import recover_params_from_ghidra
from fuzzgen4ghidra_engine.models import ParamType

def test_basic_int_params():
    ghidra_sig = {
        "params": [
            {"name": "flags", "type": "int", "size": 4},
            {"name": "count", "type": "uint32_t", "size": 4},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert len(params) == 2
    assert params[0].type == ParamType.INT
    assert params[0].c_type == "int"
    assert params[1].c_type == "uint32_t"

def test_buffer_param():
    ghidra_sig = {
        "params": [
            {"name": "buf", "type": "byte *", "size": 8},
            {"name": "len", "type": "int", "size": 4},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert params[0].type == ParamType.BUFFER
    assert params[0].length_param == 1

def test_struct_pointer():
    ghidra_sig = {
        "params": [
            {"name": "ctx", "type": "my_context_t *", "size": 8},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert params[0].type == ParamType.STRUCT_PTR

def test_void_pointer_is_buffer():
    ghidra_sig = {
        "params": [
            {"name": "data", "type": "void *", "size": 8},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert params[0].type == ParamType.BUFFER

def test_function_pointer():
    ghidra_sig = {
        "params": [
            {"name": "callback", "type": "code *", "size": 8},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert params[0].type == ParamType.FUNC_PTR
