"""Width/precision parser source slices through return or first real helper/error call."""
import pathlib,os,json,struct,random,subprocess
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
OUT=ROOT/'argid-source';OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE="\n#include <stdint.h>\nstatic uint64_t rd(const unsigned char*p,unsigned n){uint64_t x=0;for(unsigned i=0;i<n;i++)x|=(uint64_t)p[i]<<(8*i);return x;}\nstatic void wr(unsigned char*p,uint64_t x,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(unsigned char)(x>>(8*i));}\nstatic unsigned ch(uint64_t p){return *(const unsigned char*)(uintptr_t)p;}\nvoid logic_argid(uint64_t p,uint64_t end,unsigned char *ctx,uint64_t out[3]){\n unsigned c=ch(p),value=c-'0',mode;uint64_t q=p,msg=0;\n if(c=='}'||c==':'){\n  mode=(unsigned)rd(ctx+16,4);\n  if(mode==1){msg=0x10927db;goto error;}\n  if(mode==0)wr(ctx+16,2,4);\n  uint64_t index=rd(ctx+24,8);wr(ctx+24,index+1,8);value=(unsigned)index;goto done;\n }\n if(c=='0'){q=p+1;value=0;goto manual;}\n if(c<'1'||c>'9'){msg=0x1092762;goto error;}\n q=p+1;uint64_t stop=(end-p>9)?p+9:end;\n while(q<stop){c=ch(q);if(c<'0'||c>'9')goto manual;value=value*10+c-'0';q++;}\n if(q==end)goto manual;\n c=ch(q);if(c<'0'||c>'9')goto manual;\n uint64_t large=(uint64_t)value*10+c-'0';\n if(large>=0x80000000ULL){msg=0x1092820;goto error;}\n value=(unsigned)large;q++;\n if(q!=end){c=ch(q);if(c>='0'&&c<='9'){msg=0x1092820;goto error;}}\n manual:\n mode=(unsigned)rd(ctx+16,4);\n if(mode==2){msg=0x1092796;goto error;}\n if(mode==0)wr(ctx+16,1,4);\n done:out[0]=0;out[1]=q;out[2]=value;return;\n error:out[0]=1;out[1]=msg;out[2]=0;\n}\n"
(OUT/'logic_argid.c').write_text(SOURCE);engines=[];diags=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-Wall","-Wextra","-Werror","-c",str(OUT/'logic_argid.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','error',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);u.mem_map(0x3300000,0x1000);entry=next(v for n,v,undef in syms if n=='_logic_argid' and not undef);engines.append((u,entry,sha(raw)))

start,end=0x8b47a0,0x8b493c
ref,_=engine(original);covered=set();state={}
def hook(u,pc,n,_):
 if pc==0x8b4614:state['error']=u.reg_read(UC_ARM64_REG_X0);u.emu_stop();return
 assert start<=pc<end,hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook);rng=random.Random(start);cases=0;passes=[0,0,0];failures=[];families={};outcomes={}
def inputs():
 for c in range(256):
  for mode in range(5):yield ('all-leading-bytes-and-modes',bytes([c])+b'7}x',4,mode)
 for text in [b'0',b'1',b'9',b'01',b'123456789',b'2147483646',b'2147483647',b'2147483648',b'9999999999',b'10000000000',b'12345678901',b'}',b':',b'{',b'1x',b'9}']:
  for n in range(1,len(text)+1):
   for mode in range(5):yield ('index-boundaries-and-modes',text,n,mode)
 for _ in range(16384):
  n=rng.randrange(1,18);text=bytes(rng.choice(b'0123456789{}.:x') for _ in range(n))
  yield ('random-grammar-and-modes',text,n,rng.choice([0,1,2,3,0xffffffff]))
regs=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29,UC_ARM64_REG_D8,UC_ARM64_REG_D9]
for case,(family,text,n,mode) in enumerate(inputs()):
 data=bytearray(rng.randbytes(0x1000));p=BASE+0x500+case%16;ctx=BASE+0x800+(case//16)%16;limit=p+n
 data[p-BASE:p-BASE+len(text)]=text;struct.pack_into('<I',data,ctx-BASE+16,mode)
 struct.pack_into('<Q',data,ctx-BASE+24,rng.choice([0,1,0x7fffffff,0xffffffff,0xffffffffffffffff,rng.getrandbits(64)]))
 saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x2000;fpsr=case%4;fpcr=((case//4)%4)<<22
 ref.mem_write(BASE,bytes(data));ref.mem_write(STACK,bytes([0xa5])*0x4000)
 for r,x in zip(regs,saved):ref.reg_write(r,x)
 for r,x in [(UC_ARM64_REG_X0,p),(UC_ARM64_REG_X1,limit),(UC_ARM64_REG_X2,ctx),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:ref.reg_write(r,x)
 state.clear();ref.emu_start(start,STOP,count=500)
 if 'error' in state:wanted=[1,state['error'],0]
 else:
  assert ref.reg_read(UC_ARM64_REG_PC)==STOP;assert ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
  wanted=[0,ref.reg_read(UC_ARM64_REG_X0),ref.reg_read(UC_ARM64_REG_X1)]
 memory=bytes(ref.mem_read(BASE,len(data)))
 for oi,(u,entry,_) in enumerate(engines):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes(0x4000));u.mem_write(0x3300000,bytes(0x1000))
  for r,x in zip(regs,saved):u.reg_write(r,x)
  for r,x in [(UC_ARM64_REG_X0,p),(UC_ARM64_REG_X1,limit),(UC_ARM64_REG_X2,ctx),(UC_ARM64_REG_X3,0x3300000),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,x)
  u.emu_start(entry,STOP,count=5000);got=list(struct.unpack('<3Q',bytes(u.mem_read(0x3300000,24))))
  ok=got==wanted and bytes(u.mem_read(BASE,len(data)))==memory and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR) and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR)
  passes[oi]+=int(ok)
  if not ok and len(failures)<20:failures.append({'case':case,'text':text.hex(),'length':n,'mode':mode,'opt':oi,'expected':wanted,'actual':got,'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory})
 families[family]=families.get(family,0)+1;key='return' if not wanted[0] else hex(wanted[1]);outcomes[key]=outcomes.get(key,0)+1;cases+=1
report={'image_sha256':sha(original),'entry':hex(start),'end':hex(end),'cases':cases,'families':families,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[x[2] for x in engines],'whole_function_verified':False,'limits':['Actual original entry-to-return or entry to real throw helper; exception allocation, throw and unwinding unresolved, no stub called.','Disjoint ordinary mapped input/context; nonempty input, nonwrapping forward end, mode values and automatic counter edges exercised. Overlap, faults, concurrency and MMIO excluded.','Original aggregate return x0/x1 compared; source uses explicit transfer record rather than claiming original complete exception ABI.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
