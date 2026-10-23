"""Full original entry-to-return comparisons, without fake callees."""
import hashlib, json, os, pathlib, random, struct, subprocess
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *

ROOT = pathlib.Path.cwd()
parent = (ROOT / 'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')])
ROOT = pathlib.Path.cwd()
LANE = os.environ.get('REA_LANE', 'diff')
ROWS = {
    'diff': (0x505fc, 0x5072c, '_mobilelogic_macore_event_diff_hash', 24, 0),
    'method': (0x4fe90, 0x4ffc0, '_mobilelogic_macore_event_diff_hash_method', 24, 1),
    'fields': (0xa918, 0xa95c, '_mobilelogic_macore_field_hash_a918', 18, 0),
}
start, end, symbol, width, argument_index = ROWS[LANE]
OUT = ROOT / ('macore-hashes-' + LANE)
OUT.mkdir(exist_ok=True)
original = (ROOT / 'dossiers/macore-input/target.bin').read_bytes()
assert sha(original) == '88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
SOURCE = (ROOT / 'reconstruction/macore_event_hashes.c').read_bytes()
(OUT / 'macore_event_hashes.c').write_bytes(SOURCE)
engines, diagnostics = [], []
for opt in (0, 2, 3):
    obj, lib = OUT / f'O{opt}.o', OUT / f'O{opt}.dylib'
    for argv in (
        ['clang-18', '-target', 'arm64-apple-ios17.0', f'-O{opt}', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-Wall', '-Wextra', '-Werror', '-c', str(OUT / 'macore_event_hashes.c'), '-o', str(obj)],
        ['ld64.lld-18', '-arch', 'arm64', '-platform_version', 'ios', '17.0', '17.0', '-dylib', '-undefined', 'error', str(obj), '-o', str(lib)],
    ):
        r = subprocess.run(argv, text=True, capture_output=True)
        diagnostics.append({'argv': argv, 'returncode': r.returncode, 'stderr': r.stderr})
        (OUT / 'compile.json').write_text(json.dumps(diagnostics, indent=2))
        assert r.returncode == 0, r.stderr
    raw = lib.read_bytes()
    u, syms = engine(raw)
    assert not [n for n, v, undef in syms if undef]
    entry = next(v for n, v, undef in syms if n == symbol and not undef)
    engines.append((u, entry, sha(raw)))

# Read native function starts and address mappings, not decompiler boundaries.
pos = 32
stream, text_base = None, None
for _ in range(struct.unpack_from('<I', original, 16)[0]):
    cmd, n = struct.unpack_from('<II', original, pos)
    if cmd == 0x26:
        off, size = struct.unpack_from('<II', original, pos + 8)
        stream = original[off:off + size]
    if cmd == 25 and original[pos+8:pos+24].split(b'\0')[0] == b'__TEXT':
        text_base = struct.unpack_from('<Q', original, pos + 24)[0]
    pos += n
assert stream is not None and text_base is not None
starts, a, value, shift = [], text_base, 0, 0
for byte in stream:
    value |= (byte & 127) << shift
    if byte & 128:
        shift += 7
        continue
    if not value:
        break
    a += value
    starts.append(a)
    value = shift = 0
assert start in starts and starts[starts.index(start)+1] == end
code_offset = va_to_offset(original, start)
code = original[code_offset:code_offset+end-start]
assert len(code) == end-start
ref, _ = engine(original)
covered, public_writes = set(), {}

def original_hook(u, pc, n, _):
    assert start <= pc < end, hex(pc)
    covered.add(pc)

def write_hook(u, access, address, size, value, _):
    if BASE <= address < BASE + SIZE:
        public_writes[id(u)] += 1

ref.hook_add(UC_HOOK_CODE, original_hook)
for u in [ref] + [x[0] for x in engines]:
    public_writes[id(u)] = 0
    u.hook_add(UC_HOOK_MEM_WRITE, write_hook)
regs = list(range(UC_ARM64_REG_X19, UC_ARM64_REG_X28+1)) + [UC_ARM64_REG_X29] + [UC_ARM64_REG_D8, UC_ARM64_REG_D9, UC_ARM64_REG_D10, UC_ARM64_REG_D11, UC_ARM64_REG_D12, UC_ARM64_REG_D13, UC_ARM64_REG_D14, UC_ARM64_REG_D15]
rng = random.Random(start)
passes, failures, families = [0, 0, 0], [], {}
cases = 32768
initial = rng.randbytes(SIZE)
for u in [ref] + [x[0] for x in engines]:
    u.mem_write(BASE, initial)

def scalar_oracle(data):
    if LANE != 'fields':
        return int.from_bytes(data[:8], 'little') | int.from_bytes(data[8:16], 'little') | int.from_bytes(data[16:24], 'little')
    return sum(data[j] << (8*i) for i, j in enumerate((16,17,12,13,0,1,4,8)))

for case in range(cases):
    family = 'random'
    data = bytearray(rng.randbytes(width))
    if case < width*8:
        family = 'one-hot-input-bits'
        data = bytearray(width)
        data[case//8] = 1 << (case % 8)
    elif case < 2*width*8:
        family = 'one-cold-input-bits'
        j = case-width*8
        data = bytearray(b'\xff'*width)
        data[j//8] ^= 1 << (j % 8)
    elif case < 2*width*8+width*256:
        family = 'every-value-in-each-byte'
        j = case-2*width*8
        data = bytearray(width)
        data[j//256] = j % 256
    elif case % 4 == 0:
        family = 'or-collisions-and-overlap'
        data = bytearray([0x55 if (case//4)%2 else 0xaa] * width)
        data[case % width] = rng.randrange(256)
    families[family] = families.get(family, 0) + 1
    # 16 input alignments; guard bytes before and after are included.
    ptr = BASE + 0x100 + case % 16
    chunk = rng.randbytes(16) + bytes(data) + rng.randbytes(16)
    saved = [rng.getrandbits(64) for _ in regs]
    fpcr = (((case//4) % 4) << 22) | (((case//16) % 4) << 24)
    fpsr = (case * 0x01010101) & 0xf800009f
    hash_object = rng.getrandbits(64)  # deliberately unmapped; it must be unused

    def initialize(u):
        u.mem_write(BASE+0x100-16, bytes(128))
        u.mem_write(ptr-16, chunk)
        u.mem_write(STACK, bytes([0xa5])*0x4000)
        public_writes[id(u)] = 0
        for r,v in zip(regs,saved): u.reg_write(r,v)
        u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
        for r,v in ((UC_ARM64_REG_X0, hash_object if argument_index else ptr), (UC_ARM64_REG_X1,ptr if argument_index else rng.getrandbits(64)), (UC_ARM64_REG_X30,STOP), (UC_ARM64_REG_SP,STACK+0x3000), (UC_ARM64_REG_FPCR,fpcr), (UC_ARM64_REG_FPSR,fpsr)):
            u.reg_write(r,v)

    initialize(ref)
    ref.emu_start(start,STOP,count=200)
    wanted = ref.reg_read(UC_ARM64_REG_X0)
    assert wanted == scalar_oracle(data), (case,hex(wanted),hex(scalar_oracle(data)))
    assert ref.reg_read(UC_ARM64_REG_PC) == STOP
    assert not public_writes[id(ref)]
    memory = bytes(ref.mem_read(BASE,SIZE))
    for oi,(u,entry,_) in enumerate(engines):
        initialize(u)
        u.emu_start(entry,STOP,count=2000)
        ok = u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_X0)==wanted and not public_writes[id(u)] and bytes(u.mem_read(BASE,SIZE))==memory and u.reg_read(UC_ARM64_REG_SP)==STACK+0x3000 and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR) and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR)
        passes[oi] += int(ok)
        if not ok and len(failures)<16:
            failures.append({'case':case,'family':family,'optimization':[0,2,3][oi],'pc':hex(u.reg_read(UC_ARM64_REG_PC)),'expected':hex(wanted),'actual':hex(u.reg_read(UC_ARM64_REG_X0)),'memory_equal':bytes(u.mem_read(BASE,SIZE))==memory,'saved_registers_equal':[u.reg_read(r) for r in regs]==saved,'public_writes':public_writes[id(u)]})
report = {
    'image_sha256':sha(original),'lane':LANE,'entry':hex(start),'end_exclusive':hex(end),
    'original_bytes':end-start,'original_function_sha256':sha(code),
    'flagged_baseline_artifact_id':11863377427,'prior_flags':['decompiler_warning'],
    'cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'families':families,
    'original_instruction_locations':list(map(hex,sorted(covered))),'original_instruction_count':len(covered),
    'source_sha256':sha(SOURCE),'module_sha256':[x[2] for x in engines],'native_imports':0,
    'complete_function_bounded_test_accepted':not(cases*3-sum(passes)),
    'all_input_equivalence_proven':False,'full_native_image_rebuilt':False,
    'limits':['Ordinary readable 18/24-byte inputs, including all 16 alignment offsets; no faults, MMIO or concurrent mutation.', 'Exact original entry ABI and complete return path; full modeled public memory, no public writes, SP/callee-saved GPR/D8-D15, FPCR/FPSR compared. Hash object in method ABI is unused and not dereferenced.', 'All input bits one-hot/one-cold, each byte 0..255 in isolation, OR-collision patterns and random multi-byte combinations; finite tests do not prove all-input equivalence.'],
}
(OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
assert report['mismatches']==0
