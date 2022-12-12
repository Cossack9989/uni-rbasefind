import os
import zio
import struct
import signal
import argparse
import subprocess

from loguru import logger
from capstone import *
from unicorn import *

from unicorn.mips_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

parser = argparse.ArgumentParser(description="RTOS Firmware LOAD_ADDR Tool")
parser.add_argument('-a', '--arch', default='arm', nargs='?', const='arm',
                    choices=['arm', 'mips', 'arm64', 'mips64'])
parser.add_argument('-b', '--big_endian', action="store_true")
parser.add_argument('-p', '--path', type=str, required=True)
parser.add_argument('-m', '--min_length', type=int, default=8)
args = parser.parse_args()

if not os.path.exists(args.path):
    logger.critical("file not exists")
    exit(1)


def check_rbasefind():
    io = zio.zio(["which", "rbasefind"])
    pos = io.read_line()
    if os.path.exists(pos.decode('latin-1').strip()):
        return True
    return False


def parse_rbasefind(buffer: bytes):
    parsed = {}
    buffer = buffer.decode('latin-1')
    for line in buffer.split('\n'):
        line = line.strip()
        if not line.startswith("0x"):
            continue
        if ": " not in line:
            continue
        addr, num = [int(elem, 16 if "0x" in elem else 10) for elem in line.split(": ")]
        if addr in parsed.keys():
            parsed[addr] = max(parsed[addr], num)
        else:
            parsed[addr] = num
    return parsed, sorted(parsed, key=parsed.get, reverse=True)


def run_rbasefind(_rom_path):
    if not check_rbasefind():
        logger.error("please install rbasefind from https://github.com/marcograss/rbasefind")
        exit(1)
    cmdline = ["rbasefind", _rom_path, "-m", str(args.min_length)]
    if args.big_endian:
        cmdline.append("-b")
    proc = subprocess.Popen(
        cmdline, stdout=subprocess.PIPE
    )
    out, _ = proc.communicate()
    proc.wait()
    result, sorted_key = parse_rbasefind(out)
    if result == {} or sorted_key == []:
        return None, None
    # if len(sorted_key) > 1 and 0.8 * result[sorted_key[0]] > result[sorted_key[1]] and result[sorted_key[0]] >= 0x10:
    return sorted_key[0], result
    # return None, result


def u32(buf, signed=True, little=True):
    if signed and little:
        return struct.unpack('<i', buf)[0]
    elif signed and not little:
        return struct.unpack('>i', buf)[0]
    elif not signed and not little:
        return struct.unpack('>I', buf)[0]
    else:
        return struct.unpack('<I', buf)[0]


def sim_rom_entry(base, end, _rom_data):

    lvars = {"load_addr": 0, 'dead_addr': 0, 'from_code': True}

    if args.arch == "arm":
        UcArch, CsArch = UC_ARCH_ARM, CS_ARCH_ARM
        UcMode, CsMode = UC_MODE_THUMB | UC_MODE_ARM, CS_MODE_THUMB | CS_MODE_THUMB
        UcPC = UC_ARM_REG_PC
    elif args.arch == "arm64":
        UcArch, CsArch = UC_ARCH_ARM64, CS_ARCH_ARM64
        UcMode, CsMode = UC_MODE_ARM, CS_MODE_ARM
        UcPC = UC_ARM64_REG_PC
    elif args.arch == "mips":
        UcArch, CsArch = UC_ARCH_MIPS, CS_ARCH_MIPS
        UcMode, CsMode = UC_MODE_32 | UC_MODE_MIPS32, CS_MODE_32 | CS_MODE_MIPS32
        UcPC = UC_MIPS_REG_PC
    elif args.arch == "mips64":
        UcArch, CsArch = UC_ARCH_MIPS, CS_ARCH_MIPS
        UcMode, CsMode = UC_MODE_MIPS64, CS_MODE_MIPS64
        UcPC = UC_MIPS_REG_PC
    else:
        logger.error(f"arch {args.arch} not support")
        return None

    if args.big_endian:
        UcMode |= UC_MODE_BIG_ENDIAN
        CsMode |= CS_MODE_BIG_ENDIAN
    else:
        UcMode |= UC_MODE_LITTLE_ENDIAN
        CsMode |= CS_MODE_LITTLE_ENDIAN

    cs = Cs(CsArch, CsMode)
    uc = Uc(UcArch, UcMode)

    def unicorn_debug_instruction(_uc: Uc, address, size, user_data):

        remote_address = detect_remote_address_firstly(_uc, address, size)
        if remote_address != -1:
            raise AssertionError(f"REMOTE ADDR {remote_address:#x}")

        lvars["dead_addr"] = address

        mem = _uc.mem_read(address, size)
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(mem), size):
            logger.debug(f"\tInstr: {address:#x}:\t{cs_mnemonic}\t{cs_opstr}")

            if cs_mnemonic == "mtc0" and cs_opstr in [
                "$t0, $t4, 0", "$zero, $t4, 0"
            ]:
                uc.reg_write(UcPC, uc.reg_read(UcPC) + 0x4)
            elif cs_mnemonic == "lw" and cs_opstr == "$k1, ($k1)":
                addr_to_read = uc.reg_read(UC_MIPS_REG_K1)
                remote_address = detect_remote_address_firstly(_uc, addr_to_read, 4)
                if remote_address != -1:
                    raise AssertionError(f"REMOTE ADDR {remote_address:#x}")
                data = uc.mem_read(addr_to_read, 4)
                value = u32(data, signed=False, little=False if args.big_endian else True)
                uc.reg_write(UC_MIPS_REG_K1, value)
                uc.reg_write(UcPC, uc.reg_read(UcPC) + 0x4)

    def unicorn_debug_block(_uc: Uc, address, size, user_data):

        remote_address = detect_remote_address_firstly(_uc, address, size)
        if remote_address != -1:
            raise AssertionError(f"REMOTE ADDR {remote_address:#x}")

        logger.debug(f"Basic Block: addr={address:#x}, size={size:#x}")

    def detect_remote_address_firstly(_uc: Uc, address, size, from_code=True):

        if from_code:
            mem = _uc.mem_read(address, size)
            dead_addr = [cs_address for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(mem), size)][0]
            if address >= base + load_size:
                lvars["load_addr"] = address
                lvars["dead_addr"] = dead_addr - base + 4
                lvars["from_code"] = True
                logger.info(f"ending set to {lvars['dead_addr']:#x}")
                input()
                return address
        else:
            if address >= base + load_size:
                lvars["load_addr"] = address
                lvars["dead_addr"] += 4
                lvars["from_code"] = False
                logger.info(f"ending set to {lvars['dead_addr']:#x}")
                input()
                return address

        return -1

    def unicorn_debug_mem_access(_uc: Uc, access, address, size, value, user_data):

        remote_address = detect_remote_address_firstly(_uc, address, size, from_code=False)
        if remote_address != -1:
            raise AssertionError(f"REMOTE ADDR {remote_address:#x}")

        if access == UC_MEM_WRITE:
            logger.debug(f"\t>>> W: addr={address:#x} size={size:#x} data={value:#x}")
        else:
            logger.debug(f"\t>>> R: addr={address:#x} size={size:#x} data={value:#x}")

    def unicorn_debug_mem_invalid_access(_uc: Uc, access, address, size, value, user_data):

        detect_remote_address_firstly(_uc, address, size, from_code=False)

        if access in [UC_MEM_WRITE_UNMAPPED]:
            logger.debug(f"\t>>> INVALID W: addr={address:#x} size={size:#x} data={value:#x}")
        elif access in [UC_MEM_READ_UNMAPPED]:
            logger.debug(f"\t>>> INVALID R: addr={address:#x} size={size:#x}")
        else:
            logger.critical(f"\t>>> Unknown access {access}")

    def unicorn_debug_mem_fetch_failed(_uc: Uc, access, address, size, value, user_data):
        if access == UC_MEM_FETCH_UNMAPPED:
            logger.debug(
                f"\t\t>>> UNMAPPED Fetch: addr={address:#x} size={size:#x} data={value:#x}")
        else:
            logger.critical(
                f"\t\t>>> INVALID Fetch: addr={address:#x} size={size:#x} data={value:#x}")

    def force_crash(uc_error):
        # This function should be called to indicate to AFL that a crash occurred during emulation.
        # Pass in the exception received from Uc.emu_start()
        mem_errors = [
            UC_ERR_READ_UNMAPPED, UC_ERR_READ_PROT, UC_ERR_READ_UNALIGNED,
            UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED,
            UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED,
        ]
        if uc_error.errno in mem_errors:
            # Memory error - throw SIGSEGV
            os.kill(os.getpid(), signal.SIGSEGV)
        elif uc_error.errno == UC_ERR_INSN_INVALID:
            # Invalid instruction - throw SIGILL
            os.kill(os.getpid(), signal.SIGILL)
        else:
            # Not sure what happened - throw SIGABRT
            os.kill(os.getpid(), signal.SIGABRT)

    load_size = (len(_rom_data) + 0x1000) & 0xfffff000
    logger.info(f"will load size: {load_size:#x}")
    uc.mem_map(base, load_size, UC_PROT_ALL)
    uc.mem_write(base, _rom_data)
    # uc.mem_protect(base, load_size, UC_PROT_READ | UC_PROT_EXEC)

    uc.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
    uc.hook_add(UC_HOOK_CODE, unicorn_debug_instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, unicorn_debug_mem_access)
    uc.hook_add(
        UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_WRITE_INVALID | UC_HOOK_MEM_READ_INVALID | UC_HOOK_MEM_READ_UNMAPPED,
        unicorn_debug_mem_invalid_access
    )
    uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_INVALID, unicorn_debug_mem_fetch_failed)

    try:
        if end == -1:
            uc.emu_start(base + 0x0, base + 0x200)
        else:
            uc.emu_start(base + 0x0, base + end)
    except AssertionError as e:
        logger.info(f"Hit AssertionError {e}")
        pass
    except UcError as e:
        logger.critical(f"the emulator failed (error: {e})!")
    #     force_crash(e)

    if base == 0:
        assert lvars['load_addr'] >= 0x1000
        assert lvars['dead_addr'] > 0
        logger.success(f"RAW LOAD ADDR {lvars['load_addr']:#x}")
    else:
        logger.success(f"TRUE LOAD ADDR {base:#x}")
        return base

    top_load_addr = lvars['load_addr'] & 0xfffff000
    low_load_addr = lvars['load_addr'] & 0xfff00000
    possible_load_addr = list(range(low_load_addr, top_load_addr + 0x1000, 0x1000))

    if isinstance(possible_addr_maps, dict):
        # for k in possible_addr_maps.keys():
        #     print(hex(k), possible_addr_maps[k])
        old_res = set(possible_addr_maps.keys())
        now_res = set(possible_load_addr)
        cross = old_res & now_res
        if len(cross) > 0:
            max_matched_str_n = 0
            max_matched_addr = 0x0
            for _load_addr in list(cross):
                if possible_addr_maps[_load_addr] > max_matched_str_n:
                    max_matched_addr = _load_addr
                    max_matched_str_n = possible_addr_maps[_load_addr]
            if max_matched_addr != -1:
                return max_matched_addr

    for load_addr in range(low_load_addr, top_load_addr + 0x1000, 0x1000):
        try:
            _load_addr = sim_rom_entry(load_addr, lvars["dead_addr"], _rom_data)
            return _load_addr
        except UcError as e:
            logger.error(f"error in recursion {e}")
            continue

    logger.error("GG!")
    return 0x0


if __name__ == "__main__":

    rom_path = args.path
    rbasefind_addr, possible_addr_maps = run_rbasefind(rom_path)

    if rbasefind_addr is not None and isinstance(rbasefind_addr, int):
        logger.success(f"RBASEFIND LOAD_ADDR: {rbasefind_addr:#x}")

    rom_data = open(args.path, "rb").read()
    addr = sim_rom_entry(0x0, -1, rom_data)

    if addr is not None and isinstance(addr, int):
        logger.success(f"OPTIMIZED LOAD_ADDR: {addr:#x}")
        exit(0)

    logger.error(f"failed to analysis {rom_path}")
