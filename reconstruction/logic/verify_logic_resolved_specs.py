"""Actual C candidate for Logic 0x8b5be4, under explicit valid-dynamic-argument domain."""
import pathlib,os,json,struct,random,subprocess
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
OUT=ROOT/'resolved-specs';OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=r'''
#include <stdint.h>
static uint64_t rd(const unsigned char *p,unsigned n) {
 uint64_t x=0;for(unsigned i=0;i<n;i++)x|=(uint64_t)p[i]<<(8*i);return x;
}
/* Domain: each dynamic index is in range and resolves to original tag
 * 3/4/6/7 with a nonnegative value <= INT32_MAX. Error paths are unresolved. */
static uint32_t dynamic(const unsigned char *fmt,int32_t index) {
 uint64_t count=rd(fmt+8,8),ptr=rd(fmt+16,8),tag;
 const unsigned char *arg;
 if(count<=12) {
  tag=(rd(fmt+24,8)>>((5*(unsigned)index)&63))&31;
  arg=(const unsigned char *)(uintptr_t)(ptr+(uint64_t)index*16);
 } else {
  arg=(const unsigned char *)(uintptr_t)(ptr+(uint64_t)index*32);tag=arg[16];
 }
 return (uint32_t)rd(arg,(tag==3||tag==6)?4:8);
}
typedef struct {uint64_t first,second;} SpecPair;
SpecPair logic_resolved_specs(const unsigned char *spec,const unsigned char *fmt) {
 uint16_t flags=(uint16_t)rd(spec+2,2);
 uint32_t width=(uint32_t)rd(spec+4,4),precision=(uint32_t)rd(spec+8,4);
 if(flags&0x4000)width=dynamic(fmt,(int32_t)width);
 if(flags&0x8000)precision=dynamic(fmt,(int32_t)precision);
 SpecPair out={(spec[0]&0x7f)|((uint64_t)spec[1]<<8)|((uint64_t)width<<32),
               precision|(rd(spec+12,4)<<32)};
 return out;
}
'''
(OUT/'logic_resolved_specs.c').write_text(SOURCE);diags=[];engines=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-Wall","-Wextra","-Werror","-c",str(OUT/'logic_resolved_specs.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','error',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);entry=next(v for n,v,undef in syms if n=='_logic_resolved_specs' and not undef);engines.append((u,entry,sha(raw)))
ref,_=engine(original);covered=set();helper_visits=[]
def hook(u,pc,n,_):
 assert 0x8b5be4<=pc<0x8b5d84 or 0x8be270<=pc<0x8be2d4,hex(pc)
 if pc==0x8be270:helper_visits.append(pc)
 covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
rng=random.Random(0x8b5be4);passes=[0,0,0];failures=[];counts={};cases=12288
regs=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29,UC_ARM64_REG_D8,UC_ARM64_REG_D9]
for case in range(cases):
 count=[1,4,12,13,32,64][case%6];mode=(case//6)%4;align=(case//24)%16
 data=bytearray(rng.randbytes(0x10000));spec=BASE+0x100+align;fmt=BASE+0x200+(15-align);args=BASE+0x1000+align
 struct.pack_into('<QQ',data,fmt-BASE+8,count,args)
 packed=0
 for j in range(count):
  tag=[3,4,6,7][(case+j)%4];val=[0,1,0x7fffffff,rng.randrange(0x80000000)][(case+j)%4]
  stride=16 if count<=12 else 32;struct.pack_into('<QQ',data,args-BASE+j*stride,val,rng.getrandbits(64))
  if count<=12:packed|=tag<<(5*j)
  else:data[args-BASE+j*stride+16]=tag
 if count<=12:struct.pack_into('<Q',data,fmt-BASE+24,packed)
 flags=rng.randrange(0x4000)|(mode<<14)
 struct.pack_into('<H',data,spec-BASE+2,flags)
 width=rng.randrange(count) if mode&1 else rng.getrandbits(32)
 precision=rng.randrange(count) if mode&2 else rng.getrandbits(32)
 struct.pack_into('<II',data,spec-BASE+4,width,precision)
 # Real original stack-protector import slot points to modeled normal process
 # guard storage; no native function or error handler is replaced.
 guard=BASE+0xf000;canary=rng.getrandbits(64);struct.pack_into('<Q',data,guard-BASE,canary)
 ref.mem_write(0x1297340,struct.pack('<Q',guard))
 sp=STACK+0x2000;fpsr=case%4;fpcr=((case//4)%4)<<22;saved=[rng.getrandbits(64) for _ in regs]
 ref.mem_write(BASE,bytes(data));ref.mem_write(STACK,bytes([0xa5])*0x4000)
 for reg,val in zip(regs,saved):ref.reg_write(reg,val)
 for reg,val in [(UC_ARM64_REG_X0,spec),(UC_ARM64_REG_X1,fmt),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPCR,fpcr),(UC_ARM64_REG_FPSR,fpsr)]:ref.reg_write(reg,val)
 before=len(helper_visits);ref.emu_start(0x8b5be4,STOP,count=1000)
 assert ref.reg_read(UC_ARM64_REG_PC)==STOP
 assert len(helper_visits)-before==bool(mode&1)+bool(mode&2)
 assert ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
 assert bytes(ref.mem_read(BASE,len(data)))==bytes(data)
 expected=[ref.reg_read(UC_ARM64_REG_X0),ref.reg_read(UC_ARM64_REG_X1)];key=f'count{count}-dynamic{mode}';counts[key]=counts.get(key,0)+1
 for oi,(u,entry,_) in enumerate(engines):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes(0x4000))
  for reg,val in zip(regs,saved):u.reg_write(reg,val)
  for reg,val in [(UC_ARM64_REG_X0,spec),(UC_ARM64_REG_X1,fmt),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPCR,fpcr),(UC_ARM64_REG_FPSR,fpsr)]:u.reg_write(reg,val)
  u.emu_start(entry,STOP,count=10000);actual=[u.reg_read(UC_ARM64_REG_X0),u.reg_read(UC_ARM64_REG_X1)]
  ok=actual==expected and bytes(u.mem_read(BASE,len(data)))==bytes(data) and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR) and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR)
  passes[oi]+=int(ok)
  if not ok and len(failures)<10:failures.append({'case':case,'opt':oi,'expected':expected,'actual':actual})
report={'image_sha256':sha(original),'entry':'0x8b5be4','cases':cases,'passes_O0_O2_O3':passes,'comparisons':cases*3,'mismatches':cases*3-sum(passes),'failures':failures,'case_families':counts,'real_original_numeric_helper_calls':len(helper_visits),'original_instruction_locations':list(map(hex,sorted(covered))),'original_instruction_count':len(covered),'source_sha256':sha(SOURCE.encode()),'module_sha256':[x[2] for x in engines],'whole_function_verified':False,'source_candidate':'Actual entry/return ABI C implementation under explicit valid-argument preconditions','limits':['Uninterrupted original entry-to-return including real original numeric helper bytes at 0x8be270; no callee hooks or replacement code.','Dynamic indices valid and selected tags 3/4/6/7 carry values 0..INT32_MAX. Invalid indices, unsupported tags, conversion errors, canary corruption/abort and unwind paths excluded.','Spec, format and argument storage are disjoint mapped ordinary memory; pointer and spec alignment varied. Other alias layouts remain unverified.','Original stack-guard pointer slot initialized to allocated synthetic process guard storage; normal non-corrupted guard assumption explicit.','Does not close the enclosing Logic visitor gap or establish whole-payload equivalence.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
