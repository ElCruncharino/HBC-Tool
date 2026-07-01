import pathlib
import json
import struct
from hbctool.util import *

basepath = pathlib.Path(__file__).parent.absolute()

operand_type = {
    "Reg8": (1, to_uint8, from_uint8),
    "Reg32": (4, to_uint32, from_uint32),
    "UInt8": (1, to_uint8, from_uint8),
    "UInt16": (2, to_uint16, from_uint16),
    "UInt32": (4, to_uint32, from_uint32),
    "Addr8": (1, to_int8, from_int8),
    "Addr32": (4, to_int32, from_int32),
    "Reg32": (4, to_uint32, from_uint32),
    "Imm32": (4, to_uint32, from_uint32),
    "Double": (8, to_double, from_double)
}

f = open(f"{basepath}/data/opcode.json", "r")
opcode_operand = json.load(f)
opcode_mapper = list(opcode_operand.keys())
opcode_mapper_inv = {}
for i, v in enumerate(opcode_mapper):
    opcode_mapper_inv[v] = i

f.close()

def disassemble(bc):
    i = 0
    insts = []
    while i < len(bc):
        opcode = opcode_mapper[bc[i]]
        i+=1
        inst = (opcode, [])
        operand_ts = opcode_operand[opcode]
        for oper_t in operand_ts:
            is_str = oper_t.endswith(":S")
            if is_str:
                oper_t = oper_t[:-2]
                
            size, conv_to, _ = operand_type[oper_t]
            val = conv_to(bc[i:i+size])
            inst[1].append((oper_t, is_str, val))
            i+=size
        
        insts.append(inst)
        
    return insts

def assemble(insts):
    bc = []
    for opcode, operands in insts:
        op = opcode_mapper_inv[opcode]
        bc.append(op)
        assert len(opcode_operand[opcode]) == len(operands), f"Malicious instruction: {op}, {operands}"
        for oper_t, _, val in operands:
            assert oper_t in operand_type, f"Malicious operand type: {oper_t}"
            _, _, conv_from = operand_type[oper_t]
            bc += conv_from(val)

    return bc


_UIS = opcode_mapper_inv.get("UIntSwitchImm")
_SIS = opcode_mapper_inv.get("StringSwitchImm")

def _inst_size(op):
    return sum(operand_type[o[:-2] if o.endswith(":S") else o][0]
               for o in opcode_operand[opcode_mapper[op]])

def instruction_length(bc):
    """Byte length of the instruction part of a function, i.e. where the
    appended switch jump-tables start (or len(bc) if there are none).

    Hermes puts the UIntSwitchImm/StringSwitchImm jump-tables after a function's
    instructions, so a linear scan runs straight into that data and desyncs.
    Find the earliest table and stop there; the caller decodes [0:this] and
    keeps the tail as-is.

    Table starts at align4(ip + tableOffset). The tableOffset operand is a
    UInt32 at +2 for UIntSwitchImm, +6 for StringSwitchImm. Function bytecode is
    4-byte aligned, so aligning the relative offset matches runtime.
    """
    b = bytes(bc)
    L = len(b)
    data_start = L
    i = 0
    while i < data_start:
        op = b[i]
        if op >= len(opcode_mapper):
            return L  # can't decode; caller treats the function as non-clean
        st = i
        nxt = i + 1 + _inst_size(op)
        if nxt > L:
            return L
        if op == _UIS:
            table_off = struct.unpack_from("<I", b, st + 2)[0]
            data_start = min(data_start, (st + table_off + 3) & ~3)
        elif op == _SIS:
            table_off = struct.unpack_from("<I", b, st + 6)[0]
            data_start = min(data_start, (st + table_off + 3) & ~3)
        if nxt > data_start:
            # next instruction would run into the table region; stop here
            break
        i = nxt
    return i