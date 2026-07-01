# HBC98 module provenance

The opcode table (`data/opcode.json`) and the header/section layout
(`data/structure.json`) for Hermes bytecode **version 98** were derived from the
Hermes source at commit:

    facebook/hermes @ b054113c6dfa00cb39cc713121c8ac7be66d7fe7  (2025-07-10)

The reference headers are checked into `raw/` (`BytecodeList.def`,
`BytecodeFileFormat.h`, `SerializedLiteralGenerator.h`, `ShapeTableEntry.h`).
`tool/opcode_generator.py` regenerates `data/opcode.json` from
`raw/BytecodeList.def`.

## Notes specific to HBC98

* The `SmallFuncHeader` second word is
  `bytecodeSizeInBytes:14 | functionName:8 | numberRegCount:5 | nonPtrRegCount:5`
  (**not** `15 | 17` as in the earlier c00cc57-era layout). An overflowed small
  header packs the large-header offset as `(functionName << 24) | offset`.
* `infoOffset` / `environmentSize` were removed from the function header.
* The array/object literal buffers became a *literal value buffer* + an
  *object shape table* (`objShapeTableCount` entries of 8 bytes each).
* `UIntSwitchImm` / `StringSwitchImm` jump-tables are appended after a function's
  instructions. `translator.instruction_length()` finds them so only the
  instruction region is disassembled and the tables are left as-is.

## Verification

The opcode table matches P1sec's `hermes-dec` hbc98 module, and a full
disassemble/reassemble of a real HBC98 bundle came back byte-identical
(0 function-header mismatches vs `hermes-dec`, 39474/39474 functions clean).
