import json, pathlib, random, struct, subprocess
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT = pathlib.Path.cwd()
parent = (ROOT / 'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')])
ROOT = pathlib.Path.cwd()
OUT = ROOT / 'macore-png-finish-row-prefix'
OUT.mkdir(exist_ok=True)
original = (ROOT / 'dossiers/macore-input/target.bin').read_bytes()
assert sha(original) == '88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
source = ROOT / 'reconstruction/macore_png_finish_row_prefix.c'
(OUT / source.name).write_bytes(source.read_bytes())

engines = []
diagnostics = []
for opt in (0, 2, 3):
    obj = OUT / f'finish-prefix-O{opt}.o'
    lib = OUT / f'finish-prefix-O{opt}.dylib'
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
                 if n == '_mobilelogic_macore_png_finish_row_prefix' and not undef)
    engines.append((u, entry, sha(raw)))

reference, _ = engine(original)
ENTRY = 0x3b9a4
INTERLACE = 0x3b9c8
COMPRESS = 0x3848c
covered = set()
state = {'outcome': None}

def hook(u, pc, size, _):
    if pc == INTERLACE:
        state['outcome'] = 2
        u.emu_stop()
        return
    if pc == COMPRESS:
        state['outcome'] = 1
        u.emu_stop()
        return
    if pc != STOP:
        assert ENTRY <= pc <= 0x3ba14, hex(pc)
        covered.add(pc)

reference.hook_add(UC_HOOK_CODE, hook)
rng = random.Random(0x3b9a4)
cases = 32768
passes = [0, 0, 0]
failures = []
outcomes = {'early-return': 0, 'compress-tail': 0, 'interlace-continuation': 0}
edges = [0, 1, 2, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff]

for case in range(cases):
    context = BASE + 0x100 + (case & 15)
    data = bytearray(rng.randbytes(SIZE))
    if case < 4096:
        row = edges[case % len(edges)]
        limit = edges[(case // len(edges)) % len(edges)]
    else:
        row = rng.getrandbits(32)
        limit = rng.getrandbits(32)
    interlace = 0 if case % 3 == 0 else (1 + ((case >> 2) & 0xff))
    struct.pack_into('<I', data, context - BASE + 0x20c, row)
    struct.pack_into('<I', data, context - BASE + 0x1f8, limit)
    data[context - BASE + 0x25c] = interlace & 0xff
    data = bytes(data)
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
    reference.emu_start(ENTRY, STOP, count=32)
    outcome = state['outcome']
    if outcome is None:
        assert reference.reg_read(UC_ARM64_REG_PC) == STOP
        outcome = 0
    if outcome == 1:
        args = tuple(reference.reg_read(r) for r in
                     (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                      UC_ARM64_REG_X2, UC_ARM64_REG_X3))
        assert args == (context, 0, 0, 4)
    outcomes[['early-return', 'compress-tail', 'interlace-continuation'][outcome]] += 1
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
        actual = u.reg_read(UC_ARM64_REG_X0) & 0xffffffff
        memory_equal = bytes(u.mem_read(BASE, SIZE)) == wanted
        ok = (actual == outcome and memory_equal and
              u.reg_read(UC_ARM64_REG_FPCR) == wanted_fpcr and
              u.reg_read(UC_ARM64_REG_FPSR) == wanted_fpsr)
        passes[oi] += int(ok)
        if not ok and len(failures) < 16:
            failures.append({'case': case, 'optimization': [0, 2, 3][oi],
                             'expected': outcome, 'actual': actual,
                             'memory_equal': memory_equal})

report = {
    'image_sha256': sha(original),
    'original_function_entry': hex(ENTRY),
    'phase_entry': hex(ENTRY),
    'early_return': '0x3b9bc',
    'interlace_continuation_cut': hex(INTERLACE),
    'native_compress_tail_cut': hex(COMPRESS),
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
        'Actual _png_write_finish_row entry is executed. The early return is complete, the noninterlace path stops at the real _png_compress_IDAT tail target, and interlace processing stops at its first unresolved instruction.',
        'The compression dependency and interlace continuation are neither invoked nor stubbed.',
        '32-bit boundary grids, zero/nonzero interlace flags and deterministic random contexts are finite evidence, not an all-input proof.',
        'Full modeled public memory and FPCR/FPSR compared; native compression x0..x3 arguments are checked.'
    ],
}
(OUT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
assert report['mismatches'] == 0
