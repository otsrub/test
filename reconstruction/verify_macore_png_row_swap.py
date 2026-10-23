import json, pathlib, random, struct, subprocess
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT = pathlib.Path.cwd()
parent = (ROOT / 'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')])
ROOT = pathlib.Path.cwd()
OUT = ROOT / 'macore-png-row-swap'
OUT.mkdir(exist_ok=True)
original = (ROOT / 'dossiers/macore-input/target.bin').read_bytes()
assert sha(original) == '88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
source = ROOT / 'reconstruction/macore_png_row_swap.c'
(OUT / source.name).write_bytes(source.read_bytes())

engines = []
diagnostics = []
for opt in (0, 2, 3):
    obj = OUT / f'row-swap-O{opt}.o'
    lib = OUT / f'row-swap-O{opt}.dylib'
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
                 if n == '_mobilelogic_macore_png_row_swap' and not undef)
    engines.append((u, entry, sha(raw)))

reference, _ = engine(original)
ENTRY = 0x3ce00
CALL = 0x3ce18
covered = set()

def hook(u, pc, size, _):
    if pc == CALL:
        u.emu_stop()
        return
    assert ENTRY <= pc < CALL, hex(pc)
    covered.add(pc)

reference.hook_add(UC_HOOK_CODE, hook)
rng = random.Random(0x3ce00)
cases = 32768
passes = [0, 0, 0]
failures = []
outcomes = {'unchanged-null-previous': 0, 'swapped': 0}
edge_values = [0, 1, 4, 0xffffffffffffffff, BASE + 0x1000,
               BASE + SIZE - 1, 0x8000000000000000, 0x7fffffffffffffff]

for case in range(cases):
    context = BASE + 0x100 + (case & 15)
    data = bytearray(rng.randbytes(SIZE))
    previous = 0 if (case & 3) == 0 else (
        edge_values[(case >> 2) & 7] or 1)
    current = edge_values[(case >> 5) & 7] if case < 4096 else rng.getrandbits(64)
    struct.pack_into('<Q', data, context - BASE + 0x218, previous)
    struct.pack_into('<Q', data, context - BASE + 0x220, current)
    data = bytes(data)
    fpcr = (((case // 4) % 4) << 22) | (((case // 16) % 4) << 24)
    fpsr = (case * 0x01010101) & 0xf800009f

    reference.mem_write(BASE, data)
    reference.mem_write(STACK, bytes([0xa5]) * 0x4000)
    reference.reg_write(UC_ARM64_REG_SP, STACK + 0x2000)
    reference.reg_write(UC_ARM64_REG_X19, context)
    reference.reg_write(UC_ARM64_REG_FPCR, fpcr)
    reference.reg_write(UC_ARM64_REG_FPSR, fpsr)
    reference.emu_start(ENTRY, STOP, count=16)
    assert reference.reg_read(UC_ARM64_REG_PC) == CALL
    assert reference.reg_read(UC_ARM64_REG_X0) == context
    outcomes['swapped' if previous else 'unchanged-null-previous'] += 1
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
        memory_equal = bytes(u.mem_read(BASE, SIZE)) == wanted
        ok = (memory_equal and u.reg_read(UC_ARM64_REG_FPCR) == wanted_fpcr and
              u.reg_read(UC_ARM64_REG_FPSR) == wanted_fpsr)
        passes[oi] += int(ok)
        if not ok and len(failures) < 16:
            failures.append({'case': case, 'optimization': [0, 2, 3][oi],
                             'previous': hex(previous), 'current': hex(current),
                             'memory_equal': memory_equal})

report = {
    'image_sha256': sha(original),
    'original_function_entry': '0x3c144',
    'phase_entry': hex(ENTRY),
    'native_finish_row_call_cut': hex(CALL),
    'native_finish_row_dependency': '0x3b9a4',
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
        'Synthetic entry after the first real _png_compress_IDAT call returns; that compression dependency is neither executed nor stubbed.',
        'Original executes uninterrupted to the real _png_write_finish_row call at 0x3ce18. The row-finish callee is not invoked or faked.',
        'Null and diverse nonzero pointer bit patterns plus deterministic random contexts are finite evidence, not an all-input proof.',
        'Full modeled public memory and FPCR/FPSR compared; the real finish-row call x0 context is checked.'
    ],
}
(OUT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
assert report['mismatches'] == 0
