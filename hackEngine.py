from myWin32 import MemCtrl, Asm
from ctypes import c_byte
from enum import IntEnum, auto
import struct
import json
import sys
import os
import re


# pyinstaller --name lf2Hack --onefile --noconsole main.py
# pyinstaller main.spec

class ResolveType(IntEnum):
    replaceNewCode = auto()
    fillNop = auto()
    fillNopShift = auto()
    jmpChangeShift = auto()
    injectCode = auto()
    injectOrCondition = auto()


class InjectSet:
    opcode = None
    valType = None
    newVal = None

    def __init__(self, data):
        opcodeList = data['opcode']
        self.opcode = ''.join(opcodeList)
        self.valType = data['valType']
        if 'newVal' in data:
            self.newVal = data['newVal']


class HackUnit:
    memCtrl = None
    isFirst = True
    isMono = False
    targetAddrRaw = None
    targetAddr = None
    allocAddr = None
    memSize = None
    shiftRange = []
    regex = []

    refSet = None
    injectSet = None

    newValTxtBox = None

    desc = None
    hackType = None
    newBytecode = None
    origBytecode = None

    def __init__(self, memCtrl, isMono):
        self.memCtrl = memCtrl
        self.isMono = isMono

    def setNewBytecode(self, opcode):
        self.newBytecode = (c_byte * len(opcode)
                            )(*opcode)

    def hackMemInit(self):
        pass

    def resolve(self, sheetData):
        if 'desc' in sheetData:
            self.desc = sheetData['desc']

        if 'hackType' in sheetData:
            self.hackType = ResolveType[sheetData['hackType']]

        if 'targetAddr' in sheetData:
            self.targetAddrRaw = sheetData['targetAddr']

        if 'newBytecode' in sheetData:
            # byte array
            newBytecode = sheetData['newBytecode']
            isMatch = re.match("^([0-9a-fA-F])+$", newBytecode)
            if isMatch:
                newBytecode = bytes.fromhex(newBytecode)
                self.setNewBytecode(newBytecode)
            assert self.newBytecode != None

        if 'memSize' in sheetData:
            self.memSize = sheetData['memSize']

        if 'isShift' in sheetData:
            self.isShift = sheetData['isShift']

        if 'shiftRange' in sheetData:
            self.shiftRange = sheetData['shiftRange']

        if 'regex' in sheetData:
            r = sheetData['regex']
            self.regex = ''.join(r)

        if 'injectSet' in sheetData:
            self.injectSet = InjectSet(sheetData['injectSet'])

        if 'refSet' in sheetData:
            refSetData = sheetData['refSet']
            self.refSet = HackUnit(self.memCtrl, self.isMono)
            self.refSet.resolve(refSetData)

    def bindUI(self, ui):
        self.newValTxtBox = ui.txtBox

    def targetAddrInit(self):
        if self.isMono:
            className, methodName, offset = self.monoTargetAddrSplit()
            JITAddr = self.memCtrl.getJITAddr(
                className, methodName)
            print("%s:%s+%s = %s" %
                  (className, methodName, hex(offset), hex(JITAddr)))
            self.targetAddr = JITAddr + offset
        else:
            self.targetAddr = int(self.targetAddrRaw, 16)

        # addition HackUnit
        if self.refSet != None:
            self.refSet.targetAddrInit()

    def monoTargetAddrSplit(self):
        className, methodName, offset = re.split('[:+]', self.targetAddrRaw)
        return className, methodName, int(offset, 16)

    def findShiftAddr(self):
        startAddr = self.targetAddr + self.shiftRange[0]
        endAddr = self.targetAddr + self.shiftRange[1]
        buffer = (c_byte * (endAddr - startAddr))()
        self.memCtrl.ReadProcessMemory(startAddr, buffer)
        haystackStr = ''.join([hex(x & 0xff)[2:].zfill(2)
                               for x in buffer])
        match = [x for x in re.finditer(self.regex, haystackStr)]

        assert len(match) > 0
        matchStr = match[0].group(1)
        matchStart = haystackStr.find(matchStr)
        assert matchStart != -1
        return startAddr + matchStart // 2

    def printMem(self, isOn):
        if isOn:
            onoffDesc = "on"
            bytecode = self.newBytecode
        else:
            onoffDesc = "off"
            bytecode = self.origBytecode

        print("%s %s:%s" % (self.desc, onoffDesc, struct.unpack(
            '<%ds' % len(bytecode), bytecode)[0].hex()))

    def writeTargetMem(self, isNew):
        if isNew:
            buf = self.newBytecode
        else:
            buf = self.origBytecode
        self.memCtrl.WriteProcessMemory(
            self.targetAddr, buf)

    def hackMem(self):
        buf = (c_byte * self.memSize)()
        if self.memCtrl.ReadProcessMemory(self.targetAddr, buf):
            #  store original bytecode for the first time
            if self.isFirst:
                self.isFirst = False
                self.origBytecode = buf
            self.writeTargetMem(True)
            return True
        else:
            return False

    def resetMem(self):
        buf = (c_byte * self.memSize)()
        if self.memCtrl.ReadProcessMemory(self.targetAddr, buf):
            self.writeTargetMem(False)
            return True
        else:
            return False


class HackUnit_fillNop(HackUnit):

    def __init__(self, memCtrl, isMono):
        super(HackUnit_fillNop, self).__init__(memCtrl, isMono)

    def hackMemInit(self):
        self.setNewBytecode(b'\x90' * self.memSize)


class HackUnit_fillNopShift(HackUnit):

    def __init__(self, memCtrl, isMono):
        super(HackUnit_fillNopShift, self).__init__(memCtrl, isMono)

    def hackMemInit(self):
        self.targetAddr = self.findShiftAddr()
        self.setNewBytecode(b'\x90' * self.memSize)


class HackUnit_jmpChangeShift(HackUnit):

    def __init__(self, memCtrl, isMono):
        super(HackUnit_jmpChangeShift, self).__init__(memCtrl, isMono)

    def hackMemInit(self):
        self.targetAddr = self.findShiftAddr()
        ip = self.targetAddr + self.memSize

        refTatgetAddr = self.refSet.findShiftAddr()
        refIp = refTatgetAddr + self.refSet.memSize
        buf = (c_byte * self.refSet.memSize)()
        self.memCtrl.ReadProcessMemory(refTatgetAddr, buf)
        refJmpOffs = struct.unpack('<i', buf)[0]
        refJmpAddr = refIp + refJmpOffs

        jmpAddr = refJmpAddr - ip
        newBytecode = struct.pack('<i', jmpAddr)
        self.setNewBytecode(newBytecode)


class HackUnit_injectCode(HackUnit):
    asm = None

    def __init__(self, memCtrl, isMono):
        super(HackUnit_injectCode, self).__init__(memCtrl, isMono)
        self.asm = Asm()

    def getNewValStr(self):

        if self.injectSet.valType == "float":
            newVal = float(self.newValTxtBox.text)
            floatBytes = struct.pack('>f', newVal)
            result = ''.join([hex(x)[2:].zfill(2) for x in floatBytes])
        else:
            result = '0'
        return '0x' + result

    def allocInjectCode(self):
        newVal = self.getNewValStr()
        opcode = self.injectSet.opcode
        opcode = opcode.replace('$val', newVal)
        bytecode = self.asm.encode(opcode)
        jmpInstrAddr = self.injectCodeAddr + len(bytecode)
        jmpDestAddr = self.targetAddr + self.memSize
        bytecode += self.asm.makeJmpCode(jmpInstrAddr, jmpDestAddr)
        return (c_byte * len(bytecode))(*bytecode)

    def makeJmpToInjectCode(self):
        jmpCode = self.asm.makeJmpCode(
            self.targetAddr, self.injectCodeAddr)
        if len(jmpCode) < self.memSize:
            fillNopCount = self.memSize - len(jmpCode)
            jmpCode += ([0x90] * fillNopCount)
        return (c_byte * len(jmpCode))(*jmpCode)

    def setupInjectCode(self):
        self.injectCodeAddr = self.memCtrl.allocExecMem()
        injectCode = self.allocInjectCode()
        self.memCtrl.WriteProcessMemory(self.injectCodeAddr, injectCode)
        self.newBytecode = self.makeJmpToInjectCode()

    def restoreInsertCode(self):
        if self.injectCodeAddr != None:
            self.memCtrl.virtualFreeEX(self.injectCodeAddr)
            self.injectCodeAddr = None

    def hackMem(self):
        buf = (c_byte * self.memSize)()

        if self.memCtrl.ReadProcessMemory(self.targetAddr, buf):
            #  store original opcode for the first time
            if self.isFirst:
                self.isFirst = False
                self.origBytecode = buf
            self.setupInjectCode()
            self.writeTargetMem(True)
            return True
        else:
            return False

    def resetMem(self):
        buf = (c_byte * self.memSize)()
        if self.memCtrl.ReadProcessMemory(self.targetAddr, buf):
            self.restoreInsertCode()
            self.writeTargetMem(False)
            return True
        else:
            return False


class HackUnit_injectOrCondition(HackUnit_injectCode):

    def __init__(self, memCtrl, isMono):
        super(HackUnit_injectOrCondition, self).__init__(memCtrl, isMono)

    def getOrigJmpDestAddr(self):
        origCond = [x & 0xff for x in self.origBytecode]
        jmpOffs = struct.unpack('<i', bytes(origCond[2:]))[0]
        ip = self.targetAddr + self.memSize
        jmpDestAddr = ip + jmpOffs
        return jmpDestAddr

    def copyOrigCondCode(self, bytecode, jmpDestAddr):
        origCond = [x & 0xff for x in self.origBytecode]
        mnem = self.asm.disasm(bytes(origCond), 0x0)[0].mnemonic
        jmpCode = self.asm.makeJmpCode(
            self.injectCodeAddr + len(bytecode), jmpDestAddr, mnem)

        return jmpCode

    def allocInjectCode(self):

        jmpDestAddr = self.getOrigJmpDestAddr()
        # origin condition else jmp
        bytecode = []
        bytecode += self.copyOrigCondCode(bytecode, jmpDestAddr)
        # addition condition
        bytecode += self.asm.encode(self.injectSet.opcode)
        # origin condition else jmp
        bytecode += self.copyOrigCondCode(bytecode, jmpDestAddr)
        jmpInstrAddr = self.injectCodeAddr + len(bytecode)
        jmpDestAddr = self.targetAddr + self.memSize
        bytecode += self.asm.makeJmpCode(jmpInstrAddr, jmpDestAddr)
        return (c_byte * len(bytecode))(*bytecode)


class ProcMemoryMain:
    hackUnits = []

    def __init__(self):

        # define classed by type
        hackUnitHandlers = {
            ResolveType.fillNop: HackUnit_fillNop,
            ResolveType.fillNopShift: HackUnit_fillNopShift,
            ResolveType.jmpChangeShift: HackUnit_jmpChangeShift,
            ResolveType.injectCode: HackUnit_injectCode,
            ResolveType.injectOrCondition: HackUnit_injectOrCondition,
        }

        # use enum len to generate class array
        self.memCtrl = MemCtrl()

        with open(resource_path('config\sheet.json')) as json_file:
            jsonData = json.load(json_file)
            sheets = jsonData['sheets']
            self.procName = jsonData['procName']
            self.isMono = jsonData['isMono']
            self.hackUnits = []

            for _, sheetData in enumerate(sheets):
                type = ResolveType[sheetData['hackType']]
                h = hackUnitHandlers.get(type, HackUnit)(
                    self.memCtrl, self.isMono)
                h.resolve(sheetData)
                self.hackUnits.append(h)

    def isOpenProcess(self):
        return self.memCtrl.isOpenProcess()

    def openProcess(self):
        if self.memCtrl.openProcess(self.procName):
            if self.isMono:
                self.memCtrl.monoFeature()
            self.targetAddrInit()
            self.hackMemInit()
        else:
            return

    def hackMemInit(self):
        for h in self.hackUnits:
            h.hackMemInit()

    # set up addr by mono
    def targetAddrInit(self):
        for h in self.hackUnits:
            h.targetAddrInit()

    def hackMem(self, index):
        h = self.hackUnits[index]
        return h.hackMem()

    def resetMem(self, index):
        h = self.hackUnits[index]
        return h.resetMem()

    def closeHandle(self):
        self.memCtrl.CloseHandle()


# pyinstaller file path
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
