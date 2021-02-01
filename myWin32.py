import sys

from keystone import *
from capstone import *

from ctypes import Structure
from ctypes import c_ulong, c_byte, c_wchar_p, c_size_t, c_long, c_int, c_uint, c_char, c_ubyte, c_char_p, c_void_p, CFUNCTYPE
from ctypes import windll, cdll, CDLL, WINFUNCTYPE, sizeof, POINTER, pointer, cast, WinDLL, byref, create_string_buffer, wintypes, WinError
from ctypes.wintypes import WORD, DWORD, UINT, LPVOID
from pathlib import Path
import struct
import win32pdh
import win32pdhutil
import win32process
import os

TH32CS_SNAPMODULE = 0x00000008
INFINITE = 0xFFFFFFFF
WAIT_FAILED = 0xFFFFFFFF

loadLibraryFlags = {'DONT_RESOLVE_DLL_REFERENCES': 0x00000001}

privileges = {
    'PROCESS_ALL_ACCESS': 0x1F0FFF,
    'PROCESS_QUERY_INFORMATION': 0x0400,
    'PROCESS_VM_OPERATION': 0x0008,
    'PROCESS_VM_READ': 0x0010,
    'PROCESS_VM_WRITE': 0x0020,
}

mem_states = {
    'MEM_COMMIT': 0x1000,
    'MEM_FREE': 0x10000,
    'MEM_RESERVE': 0x2000,
}

memFree_types = {
    'MEM_COALESCE_PLACEHOLDERS': 0x1,
    'MEM_PRESERVE_PLACEHOLDER': 0x2,
    'MEM_DECOMMIT': 0x4000,
    'MEM_RELEASE': 0x8000
}

mem_types = {
    'MEM_IMAGE': 0x1000000,
    'MEM_MAPPED': 0x40000,
    'MEM_PRIVATE': 0x20000,
}
page_protections = {
    'PAGE_EXECUTE': 0x10,
    'PAGE_EXECUTE_READ': 0x20,
    'PAGE_EXECUTE_READWRITE': 0x40,
    'PAGE_EXECUTE_WRITECOPY': 0x80,
    'PAGE_NOACCESS': 0x01,
    'PAGE_READONLY': 0x02,
    'PAGE_READWRITE': 0x04,
    'PAGE_WRITECOPY': 0x08,
}

mem_states['MEM_CREATE'] = (mem_states['MEM_COMMIT']
                            | mem_states['MEM_RESERVE'])


class Asm:
    def __init__(self):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)

    def disasm(self, code, addr):
        instr = []
        for i in self.md.disasm(code, addr):
            #i.address, i.mnemonic, i.op_str
            instr.append(i)
        return instr

    def encode(self, code):
        print("code:", code)
        encoding, _ = self.ks.asm(code)
        return encoding

    def makeJmpCode(self, instrAddr, destAddr, mnem='jmp'):
        code = "%s %s;" % (mnem, hex(destAddr))
        encoding, _ = self.ks.asm(code, instrAddr)
        return encoding


class MemCtrlError(Exception):
    pass


class MemCtrl:
    PID = None
    procHandle = None
    # dll
    dllAddr = None
    mono_compile_method_addr = None
    mono_class_get_method_from_name_addr = None
    targetDllPath = None

    def __init__(self):
        self.kernel32 = WinDLL('kernel32', use_last_error=True)

    def isOpenProcess(self):
        return self.procHandle != None

    def openProcess(self, procName):
        pids = win32pdhutil.FindPerformanceAttributesByName(
            procName, None, None, win32pdh.PDH_FMT_LONG, None, True)
        print(pids)
        if len(pids) == 0:
            print("fail")
            return False
        elif len(pids) > 0:
            self.PID = pids[0]
            self.procHandle = self.kernel32.OpenProcess(
                privileges['PROCESS_ALL_ACCESS'], False, self.PID)
            self.baseAddr = win32process.EnumProcessModules(self.procHandle)[0]
            return True

    def monoFeature(self):
        self.getTargetDllPath()
        self.injectDllInit()

    def createRemoteThreadByVal(self, funcAddr, args):

        dllAddr = c_int(0)
        thread = self.kernel32.CreateRemoteThread(self.procHandle, None, None,
                                                  c_int(funcAddr), c_int(args),
                                                  None, None)
        if not thread:
            raise WinError()
        if self.kernel32.WaitForSingleObject(thread, INFINITE) == WAIT_FAILED:
            raise WinError()
        if not self.kernel32.GetExitCodeThread(thread, byref(dllAddr)):
            raise WinError()

        return dllAddr.value

    def createRemoteTreadByRef(self, funcAddr, args):

        dllAddr = c_int(0)
        argsAddr = self.allocRemoteMem(args, len(args))
        thread = self.kernel32.CreateRemoteThread(self.procHandle, None, None,
                                                  c_int(funcAddr),
                                                  c_int(argsAddr), None, None)
        if not thread:
            raise WinError()
        if self.kernel32.WaitForSingleObject(thread, INFINITE) == WAIT_FAILED:
            raise WinError()
        if not self.kernel32.GetExitCodeThread(thread, byref(dllAddr)):
            raise WinError()
        self.virtualFreeEX(argsAddr)
        return dllAddr.value

    def mono_compile_method(self, method):
        return self.createRemoteThreadByVal(self.mono_compile_method_addr,
                                            method)

    def getJITAddr(self, className, methodName):

        dllPathBytes = self.targetDllPath.encode('utf-8')
        dllPathAddr = self.allocRemoteMem(dllPathBytes, len(dllPathBytes))

        clsNameBytes = className.encode('utf-8')
        clsNameAddr = self.allocRemoteMem(clsNameBytes, len(clsNameBytes))

        funcNameBytes = methodName.encode('utf-8')
        funcNameAddr = self.allocRemoteMem(funcNameBytes, len(funcNameBytes))

        args = struct.pack("3i", dllPathAddr, clsNameAddr, funcNameAddr)
        methodId = self.createRemoteTreadByRef(
            self.mono_class_get_method_from_name_addr, args)

        self.virtualFreeEX(dllPathAddr)
        self.virtualFreeEX(clsNameAddr)
        self.virtualFreeEX(funcNameAddr)

        return self.mono_compile_method(methodId)

    def injectDllInit(self):
        path_dll = os.path.abspath("MonoInjector.dll")
        buffer = path_dll.encode("ascii")
        funcAddr = self.get_address_from_module("kernel32.dll", "LoadLibraryA")
        self.dllAddr = self.createRemoteTreadByRef(funcAddr, buffer)
        self.mono_compile_method_addr = self.getFuncAddr(
            "MonoInjector.dll", b"do_mono_compile_method", self.dllAddr)
        self.mono_class_get_method_from_name_addr = self.getFuncAddr(
            "MonoInjector.dll", b"do_mono_class_get_method_from_name",
            self.dllAddr)

    def getTargetDllPath(self):
        procName = win32process.GetModuleFileNameEx(self.procHandle, 0)
        folder = Path(procName).parent.absolute()
        for root, _, files in os.walk(folder):
            for name in files:
                if name == "Assembly-CSharp.dll":
                    self.targetDllPath = os.path.abspath(
                        os.path.join(root, name))

    def getFuncAddr(self, module, function, targetBaseAddr):
        module_addr = self.kernel32.LoadLibraryExW(
            module, None, loadLibraryFlags['DONT_RESOLVE_DLL_REFERENCES'])
        funcAddr = self.kernel32.GetProcAddress(module_addr, function)
        targetProc = funcAddr - module_addr + targetBaseAddr
        return targetProc

    def get_address_from_module(self, module, function):
        module_addr = self.kernel32.GetModuleHandleA(module.encode("ascii"))
        if not module_addr:
            raise WinError()
        funcAddr = self.kernel32.GetProcAddress(module_addr,
                                                function.encode("ascii"))
        if not module_addr:
            raise WinError()
        return funcAddr

    def ReadProcessMemory(self, targetAddr, buf):
        size = len(buf)
        return self.kernel32.ReadProcessMemory(self.procHandle, targetAddr,
                                               buf, size, 0)

    def WriteProcessMemory(self, targetAddr, buf):
        size = len(buf)
        self.kernel32.WriteProcessMemory(self.procHandle, targetAddr, buf,
                                         size, 0)

    def virtualFreeEX(self, addr):
        if self.procHandle != None:
            if (self.kernel32.VirtualFreeEx(
                    self.procHandle, addr, 0,
                    memFree_types['MEM_RELEASE']) == 0):
                raise MemCtrlError('Failed virtualFree ' +
                                   '{}'.format(self.get_last_error()))

    def allocExecMem(self):
        baseaddress = self.kernel32.VirtualAllocEx(
            self.procHandle, 0, 0x400, mem_states['MEM_COMMIT'],
            page_protections['PAGE_EXECUTE_READWRITE'])
        assert baseaddress != 0
        return baseaddress

    def allocRemoteMem(self, buffer, size):
        alloc = self.allocMem(size)
        self.WriteProcessMemory(alloc, buffer)
        return alloc

    def allocMem(self, size):
        alloc = self.kernel32.VirtualAllocEx(
            self.procHandle, None, c_int(size), mem_states['MEM_CREATE'],
            page_protections['PAGE_EXECUTE_READWRITE'])
        if not alloc:
            raise WinError()
        return alloc

    def CloseHandle(self):
        if self.procHandle != None:
            self.kernel32.CloseHandle(self.procHandle)
            print('close')


def mask(n):
    return n & 0xff


def bitConvToInt32(buf, value):
    sizeOfPtr = sizeof(c_uint)
    newBuf = map(mask, buf[value:value + sizeOfPtr])
    return struct.unpack("<I", bytes(newBuf))[0]
