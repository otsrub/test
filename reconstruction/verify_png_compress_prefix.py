"""Compare the uninterrupted original compressor entry to its first calls."""
import hashlib
import json
import pathlib
import random
import struct
import subprocess
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho, write

sha = lambda b: hashlib.sha256(b).hexdigest()
parent = pathlib.Path('prior/png-compression-dossier')
code = (parent / '0x3848c-original-function.bin').read_bytes()
assert len(code) == 940 and sha(code) == 'd2f685c12ef5279b632050c6087cd5a2cf9653a38012f622543e779705b9434b'
out = pathlib.Path('png-compress-prefix')
out.mkdir(exist_ok=True)
source = pathlib.Path('reconstruction/macore_png_compress_prefix.c')
(out / source.name).write_bytes(source.read_bytes())
MEM, STACK, STOP, OUTPUT, CALLBACK_FREE, CALLBACK_ALLOC = (
    0x30000000, 0x40000000, 0x50000000, 0x60000000, 0x70000000, 0x70001000)
SIZE = 0x5000
engines, modules, diagnostics = [], [], []
for opt in (0, 2, 3):
    obj, lib = out / f'O{opt}.o', out / f'O{opt}.dylib'
    for cmd in [
        ['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding',
         '-fno-builtin','-fno-stack-protector','-Wall','-Wextra','-Werror',
         '-c',str(source),'-o',str(obj)],
        ['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0',
         '-dylib',str(obj),'-o',str(lib)]]:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        diagnostics.append({'argv':cmd,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        write(out / 'BUILD.json', diagnostics)
        assert p.returncode == 0, p.stderr
    raw = lib.read_bytes()
    segs, _, _, symbols = macho(raw)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for name, va, vs, fo, fl in segs:
        if name == '__PAGEZERO' or not vs: continue
        lo, hi = va & ~4095, (va+vs+4095) & ~4095
        u.mem_map(lo,hi-lo)
        if fl: u.mem_write(va, raw[fo:fo+fl])
    engines.append((u,symbols['_mobilelogic_png_compress_prefix']))
    modules.append({'optimization':opt,'sha256':sha(raw)})
ref = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
ref.mem_map(0x38000,0x2000)
ref.mem_write(0x3848c,code)
ref.mem_map(0x104000,0x2000)
ref.mem_map(CALLBACK_FREE,0x2000)
for u, _ in [(ref,0x3848c)] + engines:
    u.mem_map(MEM,SIZE)
    u.mem_map(STACK,0x4000)
    u.mem_map(STOP,4096)
    u.mem_map(OUTPUT,4096)
covered, state = set(), {'cut':None}
targets = {0x104a7c:0,0x104c14:1,CALLBACK_FREE:2,0x104ddc:3,CALLBACK_ALLOC:4,0x38838:5}

def hook(u, pc, size, _):
    if pc in targets:
        state['cut'] = pc
        u.emu_stop()
    else:
        assert 0x3848c <= pc < 0x38838, hex(pc)
        covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
preserved = [getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]
preserved += [getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
rng, cases, passes, failures = random.Random(0x3848c),8192,[0,0,0],[]
outcomes = {i:0 for i in range(6)}
length_edges = [0,1,255,0xfffffffe,0xffffffff,0x100000000,0x100000001,
                0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff]
for case in range(cases):
    mode = case % 6
    ctx, holder, node = MEM+128+(case&15),MEM+0x2000+(case&15),MEM+0x3000+(case&15)
    data = bytearray(rng.randbytes(SIZE))
    struct.pack_into('<I',data,ctx-MEM+0x130,0x49444154 if mode==0 else rng.choice([0,1,0x49444155,0xffffffff]))
    struct.pack_into('<Q',data,ctx-MEM+0x1a8,0 if mode in (3,4) else holder)
    struct.pack_into('<Q',data,holder-MEM,node if mode in (1,2) else 0)
    struct.pack_into('<Q',data,node-MEM,0 if case&1 else node+64)
    struct.pack_into('<Q',data,ctx-MEM+0x3e8,CALLBACK_ALLOC if mode==4 else 0)
    struct.pack_into('<Q',data,ctx-MEM+0x3f0,CALLBACK_FREE if mode==2 else 0)
    allocation_size = [0,1,0xfffffff8,0xffffffff][(case//6)%4] if case<1024 else rng.getrandbits(32)
    struct.pack_into('<I',data,ctx-MEM+0x1b0,allocation_size)
    data = bytes(data)
    input_ptr = rng.getrandbits(64)
    length = length_edges[(case//6)%len(length_edges)] if case<4096 else rng.getrandbits(64)
    flush = rng.getrandbits(32)
    fpcr, fpsr = (case%4)<<22,(case*0x01010101)&0xf800009f
    initial = [rng.getrandbits(64) for _ in preserved]
    for u, entry in [(ref,0x3848c)] + engines:
        u.mem_write(MEM,data)
        u.mem_write(STACK,bytes([0xa5])*0x4000)
        u.mem_write(OUTPUT,bytes(4096))
        for r,v in zip(preserved,initial):u.reg_write(r,v)
        u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x2000)
        u.reg_write(ac.UC_ARM64_REG_X30,STOP)
        for r,v in zip([ac.UC_ARM64_REG_X0,ac.UC_ARM64_REG_X1,ac.UC_ARM64_REG_X2,ac.UC_ARM64_REG_X3,ac.UC_ARM64_REG_X4],
                       [ctx,input_ptr,length,flush,OUTPUT]):u.reg_write(r,v)
        u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr)
        u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr)
        if u is ref:
            state['cut']=None
            u.emu_start(entry,STOP,count=256)
            target=state['cut'];assert target is not None
            kind=targets[target];assert kind==mode
            arg0=u.reg_read(ac.UC_ARM64_REG_X0)
            arg1=u.reg_read(ac.UC_ARM64_REG_X1) if kind in (0,2,4) else 0
            expected=(kind,target,arg0,arg1)
            wanted=bytes(u.mem_read(MEM,SIZE))
            wanted_fpcr=u.reg_read(ac.UC_ARM64_REG_FPCR)
            wanted_fpsr=u.reg_read(ac.UC_ARM64_REG_FPSR)
            outcomes[kind]+=1
        else:
            u.emu_start(entry,STOP,count=3000)
            actual=struct.unpack('<4Q',bytes(u.mem_read(OUTPUT,32)))
            oi=next(i for i,(engine,_) in enumerate(engines) if engine is u)
            ok=(u.reg_read(ac.UC_ARM64_REG_PC)==STOP and actual==expected and
                bytes(u.mem_read(MEM,SIZE))==wanted and
                [u.reg_read(r) for r in preserved]==initial and
                u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x2000 and
                u.reg_read(ac.UC_ARM64_REG_FPCR)==wanted_fpcr and
                u.reg_read(ac.UC_ARM64_REG_FPSR)==wanted_fpsr)
            passes[oi]+=int(ok)
            if not ok and len(failures)<12:
                failures.append({'case':case,'optimization':(0,2,3)[oi],
                                 'expected':expected,'actual':actual})
report={'image_sha256':'88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5',
        'original_function':'0x3848c','cases':cases,'comparisons':cases*3,'passes':passes,
        'mismatches':cases*3-sum(passes),'failures':failures,'first_call_outcomes':outcomes,
        'original_instruction_locations':sorted(map(hex,covered)),
        'source_sha256':sha(source.read_bytes()),'modules':modules,
        'whole_function_verified':False,'callees_executed':False,'native_stubs_used':False,
        'limits':['Original entry through exact first calls only; no successful callback simulation.',
                  'Stable valid allocated context/list-node memory; no fault/race equivalence claim.',
                  'Internal live registers/private compiler stack differ; source-return ABI checked.',
                  'No complete compressor source closure or native image replacement.']}
write(out/'REPORT.json',report)
print(json.dumps(report,indent=2))
assert passes==[cases]*3 and not failures
