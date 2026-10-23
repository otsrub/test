"""Recover Logic UTF-8 decoder 0x8ba1c0..0x8ba3b4, preserving reload order."""
import pathlib,os,json,struct,random,subprocess
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
OUT=ROOT/'utf8-source';OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=r'''
#include <stdint.h>
static uint64_t rd(const unsigned char *p) {uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void wr(unsigned char *p,uint64_t v) {for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));}
static unsigned char at(uint64_t p,unsigned i) {return *(const unsigned char *)(uintptr_t)(p+i);}
uint32_t logic_utf8_decode(unsigned char *s) {
 const uint32_t error=0x8000fffdU;uint64_t p=rd(s);unsigned lead=at(p,0),n=0;
 for(unsigned bit=128;bit && (lead&bit);bit>>=1)++n;
 if(n==0) {wr(s,p+1);return at(p,0);}
 if(n<2||n>4) {wr(s,p+1);return error;}
 uint64_t available=rd(s+8)-p;
 if((available>>63)||available<n) {wr(s,p+1);return error;}
 for(unsigned i=1;i<n;i++) if((at(p,i)&0xc0)!=0x80) {wr(s,p+1);return error;}
 wr(s,p+1);unsigned a=at(p,0)&(n==2?31:n==3?15:7);
 if(n==2) {wr(s,p+2);if(a<2)return error;return (a<<6)|(at(p,1)&63);}
 wr(s,p+2);unsigned b=at(p,1);unsigned prefix=(a<<12)|((b&63)<<6);
 if(n==3) {
  wr(s,p+3);if(prefix<0x800)return error;
  unsigned c=at(p,2)&63;return (prefix&0xf800)==0xd800?error:prefix|c;
 }
 wr(s,p+3);unsigned c=at(p,2);wr(s,p+4);
 if(prefix<0x400)return error;
 unsigned result=(((prefix|(c&63))<<6)|(at(p,3)&63));
 return (prefix>>10)<17?result:error;
}
'''
(OUT/'logic_utf8_decode.c').write_text(SOURCE);diags=[];engines=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-Wall","-Wextra","-Werror","-c",str(OUT/'logic_utf8_decode.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','error',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);entry=next(v for n,v,undef in syms if n=='_logic_utf8_decode' and not undef);engines.append((u,entry,sha(raw)))
ref,_=engine(original);covered=set()
def hook(u,pc,n,_):
 assert 0x8ba1c0<=pc<0x8ba3b4,hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook);rng=random.Random(0x8ba1c0);passes=[0,0,0];failures=[];families={}
regs=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29,UC_ARM64_REG_D8,UC_ARM64_REG_D9]
def inputs():
 for a in range(256):
  for b in range(256):yield ('all-two-byte-prefixes',bytes([a,b,0x80,0x80]),4,False)
 for lead in range(256):
  for size in [-1,0,1,2,3,4,5]:
   for _ in range(4):yield ('length-and-continuations',bytes([lead])+rng.randbytes(3),size,False)
 for a in range(0xe0,0xf8):
  for b in range(0x80,0xc0):
   for size in [2,3,4]:yield ('valid-continuation-boundaries',bytes([a,b,0x80,0xbf]),size,False)
 for _ in range(8192):yield ('overlap-reload-order',rng.randbytes(4),rng.randrange(-1,6),True)
cases=0
for case,(family,seq,size,alias) in enumerate(inputs()):
 data=bytearray(rng.randbytes(0x1000));s=BASE+0x200+(case%16);p=BASE+0x500+(case%16)
 if alias:p=s+(case%24)-4
 data[p-BASE:p-BASE+4]=seq
 struct.pack_into('<QQ',data,s-BASE,p,p+size)
 # Pointer/end installation may change aliased input bytes, intentionally.
 saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x2000;fpsr=case%4;fpcr=((case//4)%4)<<22
 ref.mem_write(BASE,bytes(data));ref.mem_write(STACK,bytes([0xa5])*0x4000)
 for reg,v in zip(regs,saved):ref.reg_write(reg,v)
 for reg,v in [(UC_ARM64_REG_X0,s),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:ref.reg_write(reg,v)
 ref.emu_start(0x8ba1c0,STOP,count=300);assert ref.reg_read(UC_ARM64_REG_PC)==STOP
 assert ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
 value=ref.reg_read(UC_ARM64_REG_X0);memory=bytes(ref.mem_read(BASE,len(data)))
 for oi,(u,entry,_) in enumerate(engines):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes(0x4000))
  for reg,v in zip(regs,saved):u.reg_write(reg,v)
  for reg,v in [(UC_ARM64_REG_X0,s),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(reg,v)
  u.emu_start(entry,STOP,count=5000)
  ok=u.reg_read(UC_ARM64_REG_X0)==value and bytes(u.mem_read(BASE,len(data)))==memory and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR) and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR)
  passes[oi]+=int(ok)
  if not ok and len(failures)<20:failures.append({'case':case,'family':family,'alias':alias,'initial_input':bytes(data[p-BASE:p-BASE+4]).hex(),'size':size,'optimization':oi,'original_result':value,'compiled_result':u.reg_read(UC_ARM64_REG_X0),'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory})
 families[family]=families.get(family,0)+1;cases+=1
off=va_to_offset(original,0x8ba1c0);code=original[off:off+500]
report={'image_sha256':sha(original),'entry':'0x8ba1c0','end':'0x8ba3b4','original_bytes':500,'original_slice_sha256':sha(code),'cases':cases,'families':families,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[x[2] for x in engines],'complete_function_bounded_tests_passed':sum(passes)==cases*3,'all_input_equivalence_proven':False,'limits':['Complete original entry-to-return execution; no external callees or stubs.','Mapped normal memory and non-wrapping pointers; logical end may precede cursor but referenced bytes remain physically mapped. Faults, MMIO, concurrency and asynchronous observation excluded.','All 65536 two-byte prefixes and selected multi-byte, truncation, overlong, surrogate, out-of-range and aliasing cases; finite tests are not all-input proof.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
