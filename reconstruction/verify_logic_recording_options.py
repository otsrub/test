import hashlib
import json
import pathlib
import random
import struct
import subprocess

from unicorn import Uc, UC_ARCH_ARM64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_ARM
from unicorn.arm64_const import *

ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "logic-recording-options"
OUT.mkdir(exist_ok=True)
ORIGINAL = (ROOT / "logic-input" / "target.bin").read_bytes()
ORIGINAL_SHA = "8dc0169c2d2bd0b15a48340a9f1c1508315cd33a2cce3f49704de5ba51734287"
assert hashlib.sha256(ORIGINAL).hexdigest() == ORIGINAL_SHA

STACK = 0x3100000
STOP = 0x3200000
ORIGINAL_GLOBALS = (0x153448A, 0x153448C)
FUNCTIONS = {
    "cycle_get": (0xD1243C, "_mobilelogic_recording_options_audio_cycle_get"),
    "cycle_set": (0xD12448, "_mobilelogic_recording_options_audio_cycle_set"),
    "no_cycle_get": (0xD12454, "_mobilelogic_recording_options_audio_no_cycle_get"),
    "no_cycle_set": (0xD12460, "_mobilelogic_recording_options_audio_no_cycle_set"),
}
GLOBAL_SYMBOLS = (
    "_mobilelogic_recording_options_audio_cycle",
    "_mobilelogic_recording_options_audio_no_cycle",
)
EXPECTED_OPCODES = {
    "cycle_get": "084100d00015c979c0035fd6",
    "cycle_set": "084100d000150979c0035fd6",
    "no_cycle_get": "084100d00019c979c0035fd6",
    "no_cycle_set": "084100d000190979c0035fd6",
}


def cstr(blob, at):
    return blob[at:].split(b"\0", 1)[0].decode("utf-8", "replace")


def macho(blob):
    assert blob[:4] == bytes.fromhex("cffaedfe")
    ncmds = struct.unpack_from("<I", blob, 16)[0]
    pos = 32
    segments = []
    symtab = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", blob, pos)
        if cmd == 0x19:
            vm, vmsz, off, filesz = struct.unpack_from("<QQQQ", blob, pos + 24)
            segments.append((vm, vmsz, off, filesz))
        elif cmd == 0x2:
            symtab = struct.unpack_from("<IIII", blob, pos + 8)
        pos += size
    symbols = {}
    if symtab:
        off, count, stroff, strsize = symtab
        strings = blob[stroff : stroff + strsize]
        for i in range(count):
            si, kind, section, desc, value = struct.unpack_from("<IBBHQ", blob, off + 16 * i)
            if si and not (kind & 0xE0):
                symbols[cstr(strings, si)] = (value, (kind & 0x0E) == 0)
    return segments, symbols


def engine(blob):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    segments, symbols = macho(blob)
    mapped = set()
    for vm, vmsz, off, filesz in segments:
        if not vmsz:
            continue
        lo, hi = vm & ~0xFFF, (vm + vmsz + 0xFFF) & ~0xFFF
        for page in range(lo, hi, 0x1000):
            if page not in mapped:
                u.mem_map(page, 0x1000)
                mapped.add(page)
        if filesz:
            u.mem_write(vm, blob[off : off + filesz])
    u.mem_map(STACK, 0x4000)
    return u, symbols


ref, _ = engine(ORIGINAL)
engines = []
modules = []
diagnostics = []
for opt in (0, 2, 3):
    obj = OUT / f"recording-options-O{opt}.o"
    dylib = OUT / f"recording-options-O{opt}.dylib"
    commands = [
        ["clang-18", "-target", "arm64-apple-ios17.0", f"-O{opt}", "-ffreestanding", "-Wall", "-Wextra", "-Werror", "-c", str(ROOT / "logic_recording_options.c"), "-o", str(obj)],
        ["ld64.lld-18", "-arch", "arm64", "-platform_version", "ios", "17.0", "17.0", "-dylib", "-undefined", "error", str(obj), "-o", str(dylib)],
    ]
    for argv in commands:
        result = subprocess.run(argv, text=True, capture_output=True)
        diagnostics.append({"argv": argv, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        (OUT / "compile-diagnostics.json").write_text(json.dumps(diagnostics, indent=2) + "\n")
        print(result.stderr, flush=True)
        result.check_returncode()
    raw = dylib.read_bytes()
    u, symbols = engine(raw)
    assert not [name for name, (_, undefined) in symbols.items() if undefined]
    entries = {key: symbols[symbol][0] for key, (_, symbol) in FUNCTIONS.items()}
    globals_ = tuple(symbols[symbol][0] for symbol in GLOBAL_SYMBOLS)
    engines.append((u, entries, globals_))
    modules.append({"optimization": f"O{opt}", "sha256": hashlib.sha256(raw).hexdigest()})

# Establish exact original boundaries/opcodes independently of the old warning.
for key, (entry, _) in FUNCTIONS.items():
    assert ORIGINAL[entry : entry + 12].hex() == EXPECTED_OPCODES[key]

covered = {key: set() for key in FUNCTIONS}
current_original = [None]


def cover_original(u, address, size, user):
    key = current_original[0]
    if key is not None and FUNCTIONS[key][0] <= address < FUNCTIONS[key][0] + 12:
        covered[key].add(address)


ref.hook_add(UC_HOOK_CODE, cover_original)
callee = [
    UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22,
    UC_ARM64_REG_X23, UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26,
    UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29,
]
fcallee = [UC_ARM64_REG_D8, UC_ARM64_REG_D9, UC_ARM64_REG_D10, UC_ARM64_REG_D11]
rng = random.Random(0xD1243C)
passes = {key: [0, 0, 0] for key in FUNCTIONS}
failures = []
cases = 65536


def prepare(u, globals_, values, x0, gprs, fprs, fpcr, fpsr):
    u.mem_write(STACK, bytes(0x4000))
    u.mem_write(globals_[0], struct.pack("<h", values[0]))
    u.mem_write(globals_[1], struct.pack("<h", values[1]))
    u.reg_write(UC_ARM64_REG_SP, STACK + 0x2000)
    u.reg_write(UC_ARM64_REG_X0, x0)
    u.reg_write(UC_ARM64_REG_X30, STOP)
    u.reg_write(UC_ARM64_REG_CPACR_EL1, 3 << 20)
    u.reg_write(UC_ARM64_REG_FPCR, fpcr)
    u.reg_write(UC_ARM64_REG_FPSR, fpsr)
    for reg, value in zip(callee, gprs):
        u.reg_write(reg, value)
    for reg, value in zip(fcallee, fprs):
        u.reg_write(reg, value)


def snapshot(u, globals_, is_getter):
    return {
        "globals": [struct.unpack("<h", bytes(u.mem_read(p, 2)))[0] for p in globals_],
        "return": u.reg_read(UC_ARM64_REG_X0) if is_getter else None,
        "sp": u.reg_read(UC_ARM64_REG_SP),
        "gprs": [u.reg_read(r) for r in callee],
        "fprs": [u.reg_read(r) for r in fcallee],
        "fpcr": u.reg_read(UC_ARM64_REG_FPCR),
        "fpsr": u.reg_read(UC_ARM64_REG_FPSR),
    }


for case in range(cases):
    signed = case if case < 0x8000 else case - 0x10000
    other = ((case * 40503 + 17) & 0xFFFF)
    other = other if other < 0x8000 else other - 0x10000
    x0 = (rng.getrandbits(48) << 16) | case
    gprs = [rng.getrandbits(64) for _ in callee]
    fprs = [rng.getrandbits(64) for _ in fcallee]
    fpcr = ((case & 3) << 22) | ((case & 4) << 22) | ((case & 8) << 22)
    fpsr = (case * 0x01010101) & 0xF800009F
    for key in FUNCTIONS:
        is_cycle = key.startswith("cycle_")
        is_getter = key.endswith("_get")
        initial = (signed, other) if is_cycle else (other, signed)
        prepare(ref, ORIGINAL_GLOBALS, initial, x0, gprs, fprs, fpcr, fpsr)
        current_original[0] = key
        ref.emu_start(FUNCTIONS[key][0], STOP, count=8)
        current_original[0] = None
        wanted = snapshot(ref, ORIGINAL_GLOBALS, is_getter)
        for oi, (u, entries, globals_) in enumerate(engines):
            prepare(u, globals_, initial, x0, gprs, fprs, fpcr, fpsr)
            u.emu_start(entries[key], STOP, count=100)
            got = snapshot(u, globals_, is_getter)
            ok = got == wanted
            passes[key][oi] += int(ok)
            if not ok and len(failures) < 16:
                failures.append({"case": case, "function": key, "optimization": [0, 2, 3][oi], "fields": [name for name in wanted if wanted[name] != got[name]]})

report = {
    "original_image_sha256": ORIGINAL_SHA,
    "functions": [
        {
            "name": key,
            "entry": hex(entry),
            "end_exclusive": hex(entry + 12),
            "original_bytes": 12,
            "original_opcode_hex": EXPECTED_OPCODES[key],
            "original_instruction_locations": [hex(x) for x in sorted(covered[key])],
            "passes_O0_O2_O3": passes[key],
        }
        for key, (entry, _) in FUNCTIONS.items()
    ],
    "cases_per_function": cases,
    "comparisons": cases * len(FUNCTIONS) * len(engines),
    "mismatches": cases * len(FUNCTIONS) * len(engines) - sum(sum(v) for v in passes.values()),
    "failures": failures,
    "source_sha256": hashlib.sha256((ROOT / "logic_recording_options.c").read_bytes()).hexdigest(),
    "modules": modules,
    "native_imports": 0,
    "scope": "Four complete three-instruction Logic accessors. Exhaustive 16-bit getter state and setter low-16 input domains; unrelated paired global, signed return ABI, balanced SP, callee-saved GPR/FP registers, FPCR and FPSR compared across O0/O2/O3. Ordinary coherent module storage; concurrency, faults and final whole-image link layout excluded.",
    "whole_functions_bounded_test_accepted": True,
    "all_input_equivalence_proven": False,
    "whole_logic_image_rebuilt": False,
}
(OUT / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
assert report["mismatches"] == 0
