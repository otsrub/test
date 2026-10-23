import json, pathlib, random, struct, subprocess
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT = pathlib.Path.cwd()
parent = (ROOT / 'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')])
ROOT = pathlib.Path.cwd()
OUT = ROOT / 'macore-png-post-finish'
OUT.mkdir(exist_ok=True)
original = (ROOT / 'dossiers/macore-input/target.bin').read_bytes()
assert sha(original) == '88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
source = ROOT / 'reconstruction/macore_png_post_finish.c'
(OUT / source.name).write_bytes(source.read_bytes())

engines = []
diagnostics = []
for opt in (0, 2, 3):
    obj = OUT / f'post-finish-O{opt}.o'
    lib = OUT / f'post-finish-O{opt}.dylib'
    commands = [
        ['clang-18', '-target', 'arm64-apple-ios17.0', f'-O{opt}',
         '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-Wall',
         '-Wextra', '-Werror', '-c', str(source), '-o', str(obj)],
        ['ld64.lld-18', '-arch', 'arm64', '-platform_version', 'ios', '17.0',
         '17.0', '-dylib', str(obj), '-o', str(lib)],
    ]
    for argv in commands:
        run = subprocess.run(argv, text=True, capture_output=True)
        diagnostics.append({'argv': argv, 'returncode': run.returncode,
                            'stdout': run.stdout, 'stderr': run.stderr})
        (OUT / 'compile-diagnostics.json').write_text(json.dumps(diagnostics, indent=2))
        assert run.returncode == 0, run.stderr
    raw = lib.read_bytes()
    u, symbols = engine(raw)
    entry = next(v for n, v, undef in symbols
                 if n == '_mobilelogic_macore_png_post_finish_pre_flush' and not undef)
    engines.append((u, entry, sha(raw)))

reference, _ = engine(original)
covered = set()
CALL = 0x3ce58
ENTRY = 0x3ce1c

def reference_hook(u, pc, size, _):
    if pc == CALL:
        u.emu_stop()
        return
    if pc != STOP:
        assert 0x3ce1c <= pc <= 0x3ce90, hex(pc)
        covered.add(pc)

reference.hook_add(UC_HOOK_CODE, reference_hook)

rng = random.Random(0x3ce1c)
cases = 32768
passes = [0, 0, 0]
failures = []
outcomes = {'return': 0, 'flush-call': 0}
edges = [0, 1, 2, 0x7ffffffe, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff]

for case in range(cases):
    context = BASE + 0x100 + (case & 15)
    data = bytearray(rng.randbytes(SIZE))
    if case < 4096:
        completed = edges[case & 7]
        height = edges[(case >> 3) & 7]
        current = edges[(case >> 6) & 7]
        limit = edges[(case >> 9) & 7]
    else:
        completed = rng.getrandbits(32)
        height = rng.getrandbits(32)
        current = rng.getrandbits(32)
        limit = rng.getrandbits(32)
    for off, value in [(0x294, completed), (0x290, height),
                       (0x20c, current), (0x1f8, limit)]:
        struct.pack_into('<I', data, context - BASE + off, value)
    data = bytes(data)
    fpcr = (((case // 4) % 4) << 22) | (((case // 16) % 4) << 24)
    fpsr = (case * 0x01010101) & 0xf800009f

    reference.mem_write(BASE, data)
    reference.mem_write(STACK, bytes([0xa5]) * 0x4000)
    frame = STACK + 0x2000
    reference.reg_write(UC_ARM64_REG_SP, frame)
    reference.reg_write(UC_ARM64_REG_X19, context)
    reference.reg_write(UC_ARM64_REG_X20, 0x2020202020202020)
    reference.reg_write(UC_ARM64_REG_X29, 0x2929292929292929)
    reference.reg_write(UC_ARM64_REG_X30, 0x3030303030303030)
    reference.reg_write(UC_ARM64_REG_FPCR, fpcr)
    reference.reg_write(UC_ARM64_REG_FPSR, fpsr)
    struct.pack_into('<QQ', stack := bytearray(bytes([0xa5]) * 0x40), 0x20,
                     0x2020202020202020, 0x1919191919191919)
    struct.pack_into('<QQ', stack, 0x30, 0x2929292929292929, STOP)
    reference.mem_write(frame, bytes(stack))
    reference.emu_start(ENTRY, STOP, count=64)
    expected_flush = reference.reg_read(UC_ARM64_REG_PC) == CALL
    assert expected_flush or reference.reg_read(UC_ARM64_REG_PC) == STOP
    outcomes['flush-call' if expected_flush else 'return'] += 1
    wanted = bytes(reference.mem_read(BASE, SIZE))
    wanted_fpcr = reference.reg_read(UC_ARM64_REG_FPCR)
    wanted_fpsr = reference.reg_read(UC_ARM64_REG_FPSR)

    for oi, (u, entry, _) in enumerate(engines):
        u.mem_write(BASE, data)
        u.mem_write(STACK, bytes([0x5a]) * 0x4000)
        u.reg_write(UC_ARM64_REG_SP, STACK + 0x3000)
        u.reg_write(UC_ARM64_REG_X30, STOP)
        u.reg_write(UC_ARM64_REG_X0, context)
        u.reg_write(UC_ARM64_REG_FPCR, fpcr)
        u.reg_write(UC_ARM64_REG_FPSR, fpsr)
        u.emu_start(entry, STOP, count=1000)
        actual_flush = (u.reg_read(UC_ARM64_REG_X0) & 0xffffffff) == 1
        memory_equal = bytes(u.mem_read(BASE, SIZE)) == wanted
        ok = (actual_flush == expected_flush and memory_equal and
              u.reg_read(UC_ARM64_REG_FPCR) == wanted_fpcr and
              u.reg_read(UC_ARM64_REG_FPSR) == wanted_fpsr)
        passes[oi] += int(ok)
        if not ok and len(failures) < 16:
            failures.append({'case': case, 'optimization': [0, 2, 3][oi],
                             'expected_flush': expected_flush,
                             'actual_flush': actual_flush,
                             'memory_equal': memory_equal})

report = {
    'image_sha256': sha(original),
    'original_function_entry': '0x3c144',
    'phase_entry': hex(ENTRY),
    'native_flush_call_cut': hex(CALL),
    'cases': cases,
    'comparisons': cases * 3,
    'passes_O0_O2_O3': passes,
    'mismatches': cases * 3 - sum(passes),
    'failures': failures,
    'outcomes': outcomes,
    'original_instruction_count': len(covered),
    'original_instruction_locations': list(map(hex, sorted(covered))),
    'source_sha256': sha(source.read_bytes()),
    'module_sha256': [x[2] for x in engines],
    'native_imports': 0,
    'whole_function_verified': False,
    'all_input_equivalence_proven': False,
    'limits': [
        'Synthetic post-_png_write_finish_row phase entry; the real row-finish callee is not replaced or claimed.',
        'Original executes uninterrupted to its real return or stops before the real _png_compress_IDAT flush call at 0x3ce58; no fake callee and no resumed callback.',
        '32-bit boundary grids plus deterministic random context values; finite tests do not prove all-input equivalence.',
        'Full modeled public memory and FPCR/FPSR compared. Private compiler stack layout is excluded because this is a phase, not a whole-function ABI test.'
    ],
}
(OUT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
assert report['mismatches'] == 0
