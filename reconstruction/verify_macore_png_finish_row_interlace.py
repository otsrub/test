import json, pathlib, random, struct, subprocess
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT = pathlib.Path.cwd()
parent = (ROOT / 'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')])
ROOT = pathlib.Path.cwd()
OUT = ROOT / 'macore-png-finish-row-interlace'
OUT.mkdir(exist_ok=True)
original = (ROOT / 'dossiers/macore-input/target.bin').read_bytes()
assert sha(original) == '88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
source = ROOT / 'reconstruction/macore_png_finish_row_interlace.c'
(OUT / source.name).write_bytes(source.read_bytes())

engines, diagnostics = [], []
for opt in (0, 2, 3):
    obj = OUT / f'interlace-O{opt}.o'
    lib = OUT / f'interlace-O{opt}.dylib'
    for argv in [
        ['clang-18', '-target', 'arm64-apple-ios17.0', f'-O{opt}',
         '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-Wall',
         '-Wextra', '-Werror', '-c', str(source), '-o', str(obj)],
        ['ld64.lld-18', '-arch', 'arm64', '-platform_version', 'ios', '17.0',
         '17.0', '-dylib', str(obj), '-o', str(lib)],
    ]:
        run = subprocess.run(argv, text=True, capture_output=True)
        diagnostics.append({'argv': argv, 'returncode': run.returncode,
                            'stdout': run.stdout, 'stderr': run.stderr})
        (OUT / 'compile-diagnostics.json').write_text(json.dumps(diagnostics, indent=2))
        assert run.returncode == 0, run.stderr
    raw = lib.read_bytes()
    u, symbols = engine(raw)
    entry = next(v for n, v, undef in symbols
                 if n == '_mobilelogic_macore_png_finish_row_interlace' and not undef)
    engines.append((u, entry, sha(raw)))

reference, _ = engine(original)
ENTRY, COMPRESS, BZERO = 0x3b9c8, 0x3848c, 0x1049c8
covered, state = set(), {'outcome': None}

def hook(u, pc, size, _):
    if pc == COMPRESS:
        state['outcome'] = 1
        u.emu_stop()
    elif pc == BZERO:
        state['outcome'] = 2
        u.emu_stop()
    elif pc != STOP:
        assert ENTRY <= pc < 0x3bd14, hex(pc)
        covered.add(pc)

reference.hook_add(UC_HOOK_CODE, hook)
rng = random.Random(0x3b9c8)
cases = 32768
passes = [0, 0, 0]
failures = []
outcomes = {'return': 0, 'compress-tail': 0, 'bzero-tail': 0}
pass_inputs = {str(i): 0 for i in range(256)}
edge32 = [0, 1, 2, 3, 4, 7, 8, 9, 0x7fffffff, 0x80000000,
          0xfffffff8, 0xfffffffe, 0xffffffff]

for case in range(cases):
    context = BASE + 0x100 + (case & 15)
    result = OUTPUT + 0x100
    data = bytearray(rng.randbytes(SIZE))
    old_pass = case & 0xff
    width = edge32[(case // 256) % len(edge32)] if case < 16384 else rng.getrandbits(32)
    height = edge32[(case // (256 * len(edge32))) % len(edge32)] if case < 16384 else rng.getrandbits(32)
    flags = ((case >> 8) & 0xff)
    channels = (case >> 4) & 0xff
    depth = (case >> 12) & 0xff
    previous = 0 if case % 4 == 0 else BASE + 0x9000 + (case & 0x3ff)
    data[context - BASE + 0x25d] = old_pass
    data[context - BASE + 0x12c] = flags
    data[context - BASE + 0x261] = channels
    data[context - BASE + 0x264] = depth
    struct.pack_into('<I', data, context - BASE + 0x1f0, width)
    struct.pack_into('<I', data, context - BASE + 0x1f4, height)
    struct.pack_into('<Q', data, context - BASE + 0x218, previous)
    data = bytes(data)
    pass_inputs[str(old_pass)] += 1
    fpcr = (((case // 4) % 4) << 22) | (((case // 16) % 4) << 24)
    fpsr = (case * 0x01010101) & 0xf800009f

    reference.mem_write(BASE, data)
    reference.mem_write(STACK, bytes([0xa5]) * 0x4000)
    reference.reg_write(UC_ARM64_REG_SP, STACK + 0x2000)
    reference.reg_write(UC_ARM64_REG_X0, context)
    reference.reg_write(UC_ARM64_REG_X30, STOP)
    reference.reg_write(UC_ARM64_REG_FPCR, fpcr)
    reference.reg_write(UC_ARM64_REG_FPSR, fpsr)
    state['outcome'] = None
    reference.emu_start(ENTRY, STOP, count=1000)
    outcome = state['outcome']
    if outcome is None:
        assert reference.reg_read(UC_ARM64_REG_PC) == STOP
        outcome = 0
    args = tuple(reference.reg_read(r) for r in
                 (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                  UC_ARM64_REG_X2, UC_ARM64_REG_X3))
    if outcome == 0:
        expected = (0, context, 0, 0, 0)
    elif outcome == 1:
        assert args == (context, 0, 0, 4)
        expected = (1,) + args
    else:
        expected = (2, args[0], args[1], 0, 0)
    outcomes[['return', 'compress-tail', 'bzero-tail'][outcome]] += 1
    wanted = bytes(reference.mem_read(BASE, SIZE))
    wanted_fpcr = reference.reg_read(UC_ARM64_REG_FPCR)
    wanted_fpsr = reference.reg_read(UC_ARM64_REG_FPSR)

    for oi, (u, entry, _) in enumerate(engines):
        u.mem_write(BASE, data)
        u.mem_write(OUTPUT, bytes(0x1000))
        u.mem_write(STACK, bytes([0x5a]) * 0x4000)
        u.reg_write(UC_ARM64_REG_SP, STACK + 0x3000)
        u.reg_write(UC_ARM64_REG_X30, STOP)
        u.reg_write(UC_ARM64_REG_X0, context)
        u.reg_write(UC_ARM64_REG_X1, result)
        u.reg_write(UC_ARM64_REG_FPCR, fpcr)
        u.reg_write(UC_ARM64_REG_FPSR, fpsr)
        u.emu_start(entry, STOP, count=5000)
        actual = struct.unpack('<5Q', bytes(u.mem_read(result, 40)))
        memory_equal = bytes(u.mem_read(BASE, SIZE)) == wanted
        ok = (actual == expected and memory_equal and
              u.reg_read(UC_ARM64_REG_FPCR) == wanted_fpcr and
              u.reg_read(UC_ARM64_REG_FPSR) == wanted_fpsr)
        passes[oi] += int(ok)
        if not ok and len(failures) < 16:
            failures.append({'case': case, 'optimization': [0, 2, 3][oi],
                             'expected': list(expected), 'actual': list(actual),
                             'memory_equal': memory_equal})

report = {
    'image_sha256': sha(original),
    'original_function': '_png_write_finish_row',
    'original_function_entry': '0x3b9a4',
    'phase_entry': hex(ENTRY),
    'phase_end_exclusive': '0x3bd14',
    'native_compress_tail': hex(COMPRESS),
    'native_bzero_tail': hex(BZERO),
    'cases': cases,
    'comparisons': cases * 3,
    'passes_O0_O2_O3': passes,
    'mismatches': cases * 3 - sum(passes),
    'failures': failures,
    'outcomes': outcomes,
    'pass_input_coverage': pass_inputs,
    'original_instruction_count': len(covered),
    'original_instruction_locations': list(map(hex, sorted(covered))),
    'source_sha256': sha(source.read_bytes()),
    'module_sha256': [x[2] for x in engines],
    'native_imports': 0,
    'whole_function_verified': False,
    'all_input_equivalence_proven': False,
    'limits': [
        'Executes the original Adam7 continuation from 0x3b9c8 and stops at complete return or the exact real _png_compress_IDAT/_bzero tail targets.',
        'Neither external callee is invoked or stubbed; their original register arguments are compared.',
        'All 256 incoming pass bytes, both flag paths, 32-bit overflow edges, full modeled context memory and FPCR/FPSR are compared.',
        'This phase does not include the already verified 0x3b9a4 prefix or either real external callee and is not whole-function evidence.'
    ],
}
(OUT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
assert report['mismatches'] == 0
assert all(outcomes.values())
