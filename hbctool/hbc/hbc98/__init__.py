from hbctool.util import *
from .parser import parse, export, INVALID_LENGTH
from .translator import disassemble, assemble, instruction_length
from struct import pack, unpack

NullTag = 0
TrueTag = 1 << 4
FalseTag = 2 << 4
NumberTag = 3 << 4
LongStringTag = 4 << 4
ShortStringTag = 5 << 4
ByteStringTag = 6 << 4
IntegerTag = 7 << 4
TagMask = 0x70

class HBC98:
    def __init__(self, f=None):
        if f:
            self.obj = parse(f)
            self._computeCleanFlags()
        else:
            self.obj = None

    def _computeCleanFlags(self):
        # Mark a function clean if its instruction bytes survive a disasm/reasm
        # round trip. That's all of them on a bundle we model right; if some
        # future build doesn't match, those get left alone on write (see
        # setFunction) rather than corrupted.
        obj = self.obj
        inst = obj["inst"]
        instOffset = obj["instOffset"]
        for functionHeader in obj["functionHeaders"]:
            start = functionHeader["offset"] - instOffset
            end = start + functionHeader["bytecodeSizeInBytes"]
            bc = inst[start:end]
            try:
                # instruction region only; switch tables are the tail
                ilen = instruction_length(bc)
                functionHeader["ilen"] = ilen
                instr = bc[:ilen]
                rebuilt = assemble(disassemble(instr))
                functionHeader["clean"] = bytes(rebuilt) == bytes(instr)
            except Exception:
                functionHeader["ilen"] = functionHeader["bytecodeSizeInBytes"]
                functionHeader["clean"] = False

    def export(self, f):
        export(self.getObj(), f)

    def getObj(self):
        assert self.obj, "Obj is not set."
        return self.obj

    def setObj(self, obj):
        self.obj = obj

    def getVersion(self):
        return 98

    def getHeader(self):
        return self.getObj()["header"]

    def getFunctionCount(self):
        return self.getObj()["header"]["functionCount"]

    def getFunction(self, fid, disasm=True):
        assert fid >= 0 and fid < self.getFunctionCount(), "Invalid function ID"

        functionHeader = self.getObj()["functionHeaders"][fid]
        offset = functionHeader["offset"]
        paramCount = functionHeader["paramCount"]
        registerCount = functionHeader["frameSize"]
        # HBC98 removed environmentSize from the function header.
        symbolCount = 0
        bytecodeSizeInBytes = functionHeader["bytecodeSizeInBytes"]
        functionName = functionHeader["functionName"]

        instOffset = self.getObj()["instOffset"]
        start = offset - instOffset
        # instruction region only; the [ilen:] tail (switch tables) is left as-is
        ilen = functionHeader.get("ilen", bytecodeSizeInBytes)
        bc = self.getObj()["inst"][start:start + ilen]
        insts = bc
        if disasm:
            # couldn't decode this one cleanly; empty body, bytes kept on write
            if functionHeader.get("clean", True):
                insts = disassemble(bc)
            else:
                insts = []

        try:
            functionNameStr, _ = self.getString(functionName)
        except (AssertionError, IndexError):
            # name is cosmetic in the .hasm, so a placeholder is fine
            functionNameStr = "fn" + str(functionName)
        # keep it on one line inside Function<...>
        functionNameStr = (functionNameStr
                           .replace("\n", " ").replace("\r", " ").replace("\t", " ")
                           .replace("<", "(").replace(">", ")"))

        return functionNameStr, paramCount, registerCount, symbolCount, insts, functionHeader
    
    def setFunction(self, fid, func, disasm=True):
        assert fid >= 0 and fid < self.getFunctionCount(), "Invalid function ID"

        functionName, paramCount, registerCount, symbolCount, insts, _ = func

        functionHeader = self.getObj()["functionHeaders"][fid]

        # wasn't disassembled, so don't touch its bytes
        if not functionHeader.get("clean", True):
            return

        functionHeader["paramCount"] = paramCount
        functionHeader["frameSize"] = registerCount
        # HBC98 removed environmentSize from the function header.

        # TODO : Make this work
        # functionHeader["functionName"] = functionName

        offset = functionHeader["offset"]
        bytecodeSizeInBytes = functionHeader["bytecodeSizeInBytes"]
        ilen = functionHeader.get("ilen", bytecodeSizeInBytes)

        instOffset = self.getObj()["instOffset"]
        start = offset - instOffset

        bc = insts

        if disasm:
            bc = assemble(insts)

        if ilen < bytecodeSizeInBytes:
            # switch tables at [ilen:]; rewrite instructions only, keep size
            assert len(bc) <= ilen, "Overflowed instruction length is not supported yet."
            memcpy(self.getObj()["inst"], bc, start, len(bc))
        else:
            assert len(bc) <= bytecodeSizeInBytes, "Overflowed instruction length is not supported yet."
            functionHeader["bytecodeSizeInBytes"] = len(bc)
            memcpy(self.getObj()["inst"], bc, start, len(bc))
        
    def getStringCount(self):
        return self.getObj()["header"]["stringCount"]

    def getString(self, sid):
        assert sid >= 0 and sid < self.getStringCount(), "Invalid string ID"

        stringTableEntry = self.getObj()["stringTableEntries"][sid]
        stringStorage = self.getObj()["stringStorage"]
        stringTableOverflowEntries = self.getObj()["stringTableOverflowEntries"]

        isUTF16 = stringTableEntry["isUTF16"]
        offset = stringTableEntry["offset"]
        length = stringTableEntry["length"]

        if length >= INVALID_LENGTH:
            stringTableOverflowEntry = stringTableOverflowEntries[offset]
            offset = stringTableOverflowEntry["offset"]
            length = stringTableOverflowEntry["length"]

        if isUTF16:
            length*=2

        s = bytes(stringStorage[offset:offset + length])
        return s.hex() if isUTF16 else s.decode("utf-8"), (isUTF16, offset, length)
    
    def setString(self, sid, val):
        assert sid >= 0 and sid < self.getStringCount(), "Invalid string ID"

        stringTableEntry = self.getObj()["stringTableEntries"][sid]
        stringStorage = self.getObj()["stringStorage"]
        stringTableOverflowEntries = self.getObj()["stringTableOverflowEntries"]

        isUTF16 = stringTableEntry["isUTF16"]
        offset = stringTableEntry["offset"]
        length = stringTableEntry["length"]

        if length >= INVALID_LENGTH:
            stringTableOverflowEntry = stringTableOverflowEntries[offset]
            offset = stringTableOverflowEntry["offset"]
            length = stringTableOverflowEntry["length"]
        
        if isUTF16:
            s = list(bytes.fromhex(val))
            l = len(s)//2
        else:
            l = len(val)
            s = val.encode("utf-8")
        
        assert l <= length, "Overflowed string length is not supported yet."

        memcpy(stringStorage, s, offset, len(s))
        
    def _checkBufferTag(self, buf, iid):
        keyTag = buf[iid]
        if keyTag & 0x80:
            return (((keyTag & 0x0f) << 8) | (buf[iid + 1]), keyTag & TagMask)
        else:
            return (keyTag & 0x0f, keyTag & TagMask)

    def _SLPToString(self, tag, buf, iid, ind):
        start = iid + ind
        if tag == ByteStringTag:
            type = "String"
            val = buf[start]
            ind += 1
        elif tag == ShortStringTag:
            type = "String"
            val = unpack("<H", bytes(buf[start:start+2]))[0]
            ind += 2
        elif tag == LongStringTag:
            type = "String"
            val = unpack("<L", bytes(buf[start:start+4]))[0]
            ind += 4
        elif tag == NumberTag:
            type = "Number"
            val = unpack("<d", bytes(buf[start:start+8]))[0]
            ind += 8
        elif tag == IntegerTag:
            type = "Integer"
            val = unpack("<L", bytes(buf[start:start+4]))[0]
            ind += 4
        elif tag == NullTag:
            type = "Null"
            val = None
        elif tag == TrueTag:
            type = "Boolean"
            val = True
        elif tag == FalseTag:
            type = "Boolean"
            val = False
        else:
            type = "Empty"
            val = None
        
        return type, val, ind

    def getLiteralValueBufferSize(self):
        return self.getObj()["header"]["literalValueBufferSize"]

    def getArray(self, aid):
        assert aid >= 0 and aid < self.getLiteralValueBufferSize(), "Invalid Array ID"
        tag = self._checkBufferTag(self.getObj()["literalValueBuffer"], aid)
        ind = 2 if tag[0] > 0x0f else 1
        arr = []
        t = None
        for _ in range(tag[0]):
            t, val, ind = self._SLPToString(tag[1], self.getObj()["literalValueBuffer"], aid, ind)
            arr.append(val)

        return t, arr

    def getObjKeyBufferSize(self):
        return self.getObj()["header"]["objKeyBufferSize"]

    def getObjKey(self, kid):
        assert kid >= 0 and kid < self.getObjKeyBufferSize(), "Invalid ObjKey ID"
        tag = self._checkBufferTag(self.getObj()["objKeyBuffer"], kid)
        ind = 2 if tag[0] > 0x0f else 1
        keys = []
        t = None
        for _ in range(tag[0]):
            t, val, ind = self._SLPToString(tag[1], self.getObj()["objKeyBuffer"], kid, ind)
            keys.append(val)
        
        return t, keys

    def getObjShapeTableCount(self):
        # HBC98: number of 8-byte ShapeTableEntry {keyBufferOffset, numProps}.
        return self.getObj()["header"]["objShapeTableCount"]
