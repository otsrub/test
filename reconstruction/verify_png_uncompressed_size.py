"""Complete-function original-byte tests for MACore 0x38838..0x38aa4."""
import hashlib
import json
import pathlib
import random
import struct
import subprocess
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho, write

sha=lambda b:hashlib.sha256(b).hexdigest()
code=pathlib.Path('prior/png-compression-dossier/0x38838-original-function.bin').read_bytes()
assert len(code)==620 and sha(code)=='bad810d3f6598b5b3889911cda3ac6302d10f9813bac2702f52990ee44560fde'
out=pathlib.Path('png-uncompressed-size');out.mkdir(exist_ok=True)
source=pathlib.Path('reconstruction/macore_png_uncompressed_size.c')
(out/source.name).write_bytes(source.read_bytes())
engines=[];modules=[];diagnostics=[]
for opt in (0,2,3):
    obj,lib=out/f'O{opt}.o',out/f'O{opt}.dylib'
    for cmd in [
        ['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding',
         '-fno-builtin','-fno-stack-protector','-Wall','-Wextra','-Werror',
         '-c',str(source),'-o',str(obj)],
        ['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0',
         '-dylib',str(obj),'-o',str(lib)]]:
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
        diagnostics.append({'argv':cmd,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        write(out/'BUILD.json',diagnostics);assert r.returncode==0,r.stderr
    raw=lib.read_bytes();segs,_,_,symbols=macho(raw);u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for name,va,vs,fo,fl in segs:
        if name=='__PAGEZERO' or not vs:continue
        lo,hi=va&~4095,(va+vs+4095)&~4095;u.mem_map(lo,hi-lo)
        if fl:u.mem_write(va,raw[fo:fo+fl])
    engines.append((u,symbols['_mobilelogic_png_uncompressed_size']))
    modules.append({'optimization':opt,'sha256':sha(raw)})
ref=Uc(UC_ARCH_ARM64,UC_MODE_ARM);ref.mem_map(0x38000,0x2000);ref.mem_write(0x38838,code)
MEM,STACK,STOP=0x30000000,0x40000000,0x50000000
for u,_ in [(ref,0x38838)]+engines:
    u.mem_map(MEM,4096);u.mem_map(STACK,0x4000);u.mem_map(STOP,4096)
covered=set()
def hook(u,pc,size,_):
    assert 0x38838<=pc<0x38aa4,hex(pc)
    covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
preserved=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]
preserved += [getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
rng=random.Random(0x3883838aa4);cases=32768;passes=[0,0,0];failures=[]
width_edges=[0,1,2,3,4,5,6,7,8,9,15,16,31,32,32767,32768,
             0x7fffffff,0x80000000,0xfffffff8,0xfffffff9,0xfffffffa,
             0xfffffffb,0xfffffffc,0xfffffffd,0xfffffffe,0xffffffff]
height_edges=[0,1,2,3,7,8,15,32767,32768,0x7fffffff,0x80000000,0xffffffff]
outcomes={'guard':0,'plain':0,'packed':0,'byte_scaled':0}
for case in range(cases):
    ctx=MEM+128+(case&15);data=bytearray(rng.randbytes(4096))
    if case<16384:
        width=case&31;height=(case>>5)&31;depth=(case>>10)&15;interlace=1
        rowbytes=case&0x7fff
    else:
        width=width_edges[case%len(width_edges)] if case<24576 else rng.getrandbits(32)
        height=height_edges[(case//len(width_edges))%len(height_edges)] if case<24576 else rng.randrange(32768)
        depth=case&255;interlace=(case>>3)&255
        rowbytes=rng.getrandbits(64) if case%8==0 else rng.randrange(32768)
    struct.pack_into('<I',data,ctx-MEM+0x1f0,width)
    struct.pack_into('<I',data,ctx-MEM+0x1f4,height)
    struct.pack_into('<Q',data,ctx-MEM+0x200,rowbytes)
    data[ctx-MEM+0x25c]=interlace;data[ctx-MEM+0x262]=depth
    data=bytes(data)
    outcome='guard' if rowbytes>>15 or height>>15 else 'plain' if not interlace else 'packed' if depth<=7 else 'byte_scaled'
    outcomes[outcome]+=1
    initial=[rng.getrandbits(64) for _ in preserved]
    fpcr,fpsr=(case%4)<<22,(case*0x01010101)&0xf800009f
    for index,(u,entry) in enumerate([(ref,0x38838)]+engines):
        u.mem_write(MEM,data);u.mem_write(STACK,bytes([0xa5])*0x4000)
        for reg,value in zip(preserved,initial):u.reg_write(reg,value)
        u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x2000)
        u.reg_write(ac.UC_ARM64_REG_X30,STOP);u.reg_write(ac.UC_ARM64_REG_X0,ctx)
        u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr)
        u.emu_start(entry,STOP,count=10000)
        actual=(u.reg_read(ac.UC_ARM64_REG_X0),bytes(u.mem_read(MEM,4096)),
                [u.reg_read(reg) for reg in preserved],u.reg_read(ac.UC_ARM64_REG_SP),
                u.reg_read(ac.UC_ARM64_REG_FPCR),u.reg_read(ac.UC_ARM64_REG_FPSR),
                u.reg_read(ac.UC_ARM64_REG_PC))
        assert actual[2]==initial and actual[3]==STACK+0x2000 and actual[-1]==STOP
        if index==0:expected=actual
        else:
            ok=actual==expected;passes[index-1]+=int(ok)
            if not ok and len(failures)<12:
                failures.append({'case':case,'optimization':(0,2,3)[index-1],
                                 'width':width,'height':height,'rowbytes':rowbytes,
                                 'depth':depth,'interlace':interlace,
                                 'expected_return':expected[0],'actual_return':actual[0]})
report={'image_sha256':'88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5',
        'original_function_entry':'0x38838','end_exclusive':'0x38aa4','original_bytes':620,
        'original_function_sha256':sha(code),'source_sha256':sha(source.read_bytes()),
        'cases':cases,'comparisons':cases*3,'passes':passes,'mismatches':cases*3-sum(passes),
        'failures':failures,'outcomes':outcomes,'modules':modules,
        'original_instruction_locations':sorted(map(hex,covered)),
        'whole_function_bounded_test':True,'native_callees':0,'native_imports':0,
        'limits':['Finite valid stable context memory, not an all-input proof.',
                  'Whole native image and PNG compressor integration remain open.']}
write(out/'REPORT.json',report);print(json.dumps(report,indent=2))
assert passes==[cases]*3 and not failures
