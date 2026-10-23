import json, pathlib, random, struct, subprocess
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT = pathlib.Path.cwd()
parent = (ROOT / 'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')])
ROOT = pathlib.Path.cwd()
OUT = ROOT / 'macore-png-post-flush'
OUT.mkdir(exist_ok=True)
original = (ROOT / 'dossiers/macore-input/target.bin').read_bytes()
assert sha(original) == '88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
source = ROOT / 'reconstruction/macore_png_post_flush.c'
(OUT / source.name).write_bytes(source.read_bytes())

engines = []
diagnostics = []
for opt in (0, 2, 3):
    obj = OUT / f'post-flush-O{opt}.o'
    lib = OUT / f'post-flush-O{opt}.dylib'
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
                 if n == '_mobilelogic_macore_png_post_flush' and not undef)
    engines.append((u, entry, sha(raw)))

reference, _ = engine(original)
ENTRY = 0x3ce5c
TAIL = 0x3ce7c
covered = set()

def hook(u, pc, size, _):
    if pc == TAIL:
        u.emu_stop()
        return
    if pc != STOP:
        assert ENTRY <= pc <= 0x3ce90, hex(pc)
        covered.add(pc)

reference.hook_add(UC_HOOK_CODE, hook)
rng = random.Random(0x3ce5c)
cases = 32768
passes = [0, 0, 0]
failures = []
outcomes = {'return': 0, 'callback-tail': 0}

for case in range(cases):
    context = BASE + 0x100 + (case & 15)
    data = bytearray(rng.randbytes(SIZE))
    callback = 0 if (case & 3) == 0 else (
        [1, 4, 0xffffffffffffffff, BASE + 0x5000,
         rng.getrandbits(64)][(case >> 2) % 5])
    struct.pack_into('<Q', data, context - BASE + 0x288, callback)
    struct.pack_into('<I', data, context - BASE + 0x294, rng.getrandbits(32))
    data = bytes(data)
    fpcr = (((case // 4) % 4) << 22) | (((case // 16) % 4) << 24)
    fpsr = (case * 0x01010101) & 0xf800009f

    reference.mem_write(BASE, data)
    reference.mem_write(STACK, bytes([0xa5]) * 0x4000)
    frame = STACK + 0x2000
    stack = bytearray(bytes([0xa5]) * 0x40)
    struct.pack_into('<QQ', stack, 0x20, 0x2020202020202020,
                     0x1919191919191919)
    struct.pack_into('<QQ', stack, 0x30, 0x2929292929292929, STOP)
    reference.mem_write(frame, bytes(stack))
    reference.reg_write(UC_ARM64_REG_SP, frame)
    reference.reg_write(UC_ARM64_REG_X19, context)
    reference.reg_write(UC_ARM64_REG_FPCR, fpcr)
    reference.reg_write(UC_ARM64_REG_FPSR, fpsr)
    reference.emu_start(ENTRY, STOP, count=32)
    tail = reference.reg_read(UC_ARM64_REG_PC) == TAIL
    assert tail == (callback != 0)
    if tail:
        assert reference.reg_read(UC_ARM64_REG_X0) == context
        assert reference.reg_read(UC_ARM64_REG_X1) == callback
    else:
        assert reference.reg_read(UC_ARM64_REG_PC) == STOP
    outcomes['callback-tail' if tail else 'return'] += 1
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
        actual_callback = u.reg_read(UC_ARM64_REG_X0)
        memory_equal = bytes(u.mem_read(BASE, SIZE)) == wanted
        ok = (actual_callback == callback and memory_equal and
              u.reg_read(UC_ARM64_REG_FPCR) == wanted_fpcr and
              u.reg_read(UC_ARM64_REG_FPSR) == wanted_fpsr)
        passes[oi] += int(ok)
        if not ok and len(failures) < 16:
            failures.append({'case': case, 'optimization': [0, 2, 3][oi],
                             'expected_callback': hex(callback),
                             'actual_callback': hex(actual_callback),
                             'memory_equal': memory_equal})

report = {
    'image_sha256': sha(original),
    'original_function_entry': '0x3c144',
    'phase_entry': hex(ENTRY),
    'callback_tail_cut': hex(TAIL),
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
        'Synthetic entry after the real _png_compress_IDAT flush call returns; that native dependency is neither executed nor stubbed.',
        'Original executes uninterrupted to its real epilogue or stops immediately before the optional callback branch at 0x3ce7c. The callback is never invoked or faked.',
        'Callback-null and diverse nonzero targets plus deterministic random public contexts are finite evidence, not an all-input proof.',
        'Full modeled public memory and FPCR/FPSR compared; callback target and original x0 context are checked at the tail boundary.'
    ],
}
(OUT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
assert report['mismatches'] == 0
