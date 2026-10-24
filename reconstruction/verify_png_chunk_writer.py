"""Recover real PNG chunk writer candidate and compare original first-call paths."""
import hashlib,json,pathlib,random,struct,subprocess
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
raw=pathlib.Path('prior/dependency-closure-dossier/MACore.original').read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(raw)=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
sg,sc,starts,sy=macho(raw)
def read(a,n):
 for _,v,s,o,_ in sc:
  if v<=a and a+n<=v+s:return raw[o+a-v:o+a-v+n]
 raise ValueError(hex(a))
assert 0x37c88 in starts and starts[starts.index(0x37c88)+1]==0x37e8c
out=pathlib.Path('png-chunk-writer');out.mkdir(exist_ok=True)
source=out/'macore_png_chunk_writer.c'
source.write_text('''typedef unsigned long long u64;typedef unsigned int u32;
static u64 r64(const unsigned char*p){u64 v=0;for(unsigned i=0;i<8;i++)v|=(u64)p[i]<<(i*8);return v;}
static u32 r32(const unsigned char*p){u32 v=0;for(unsigned i=0;i<4;i++)v|=(u32)p[i]<<(i*8);return v;}
static void w32(unsigned char*p,u32 v){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(i*8));}
static void be32(unsigned char*p,u32 v){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(24-i*8));}
static const char length_error[]="length exceeds PNG maximum";
static const char null_write_error[]="Call to NULL write function";
/* Descriptor of actual original return or first real callee. */
void mobilelogic_png_chunk_prefix(unsigned char*c,u32 tag,u64 data,u64 length,u64*out){
 out[0]=0;out[1]=0;out[2]=0;out[3]=0;
 if(!c)return;
 if(length>>31){out[0]=1;out[1]=0x46fcc;out[2]=(u64)c;out[3]=(u64)length_error;return;}
 w32(c+0x46c,0x22);unsigned char*h=(unsigned char*)out+64;be32(h,(u32)length);be32(h+4,tag);
 u64 callback=r64(c+0xf0);
 if(!callback){out[0]=1;out[1]=0x46fcc;out[2]=(u64)c;out[3]=(u64)null_write_error;return;}
 out[0]=2;out[1]=callback;out[2]=(u64)c;out[3]=8;
 (void)data;
}
#ifdef CHUNK_CANDIDATE
extern unsigned long crc32(unsigned long,const unsigned char*,unsigned int);
extern void png_error(void*,const char*) __attribute__((noreturn));
static void actual_write(unsigned char*c,const unsigned char*p,u64 n){
 u64 cb=r64(c+0xf0);if(!cb)png_error(c,null_write_error);
 ((void(*)(void*,const unsigned char*,u64))cb)(c,p,n);
}
static unsigned needs_crc(const unsigned char*c){u32 f=r32(c+0x128);return (c[0x213]&0x20)?((f&0x300)!=0x300):!(f&0x800);}
void mobilelogic_png_chunk_candidate(unsigned char*c,u32 tag,const unsigned char*data,u64 n){
 if(!c)return;if(n>>31)png_error(c,length_error);
 unsigned char header[8];w32(c+0x46c,0x22);be32(header,(u32)n);be32(header+4,tag);
 actual_write(c,header,8);w32(c+0x210,tag);
 u32 crc=(u32)crc32(0,0,0);w32(c+0x244,crc);
 if(needs_crc(c)){crc=(u32)crc32(crc,header+4,4);w32(c+0x244,crc);}
 w32(c+0x46c,0x42);
 if(data && n){actual_write(c,data,n);crc=r32(c+0x244);
  if(needs_crc(c)){u64 left=n;const unsigned char*p=data;do{u32 part=(u32)left;if(!part)part=0xffffffffU;crc=(u32)crc32(crc,p,part);p+=part;left-=part;}while(left);w32(c+0x244,crc);}
 }
 w32(c+0x46c,0x82);be32(header,crc);actual_write(c,header,4);
}
#endif
''')
MEM,STACK,STOP,OUTPUT,CALLBACK=0x30000000,0x40000000,0x50000000,0x60000000,0x70000000
SIZE=0x3000;build=[];modules=[];engines=[]
def load(b):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);ss,_,_,sy=macho(b)
 for name,va,vs,fo,fl in ss:
  if name=='__PAGEZERO' or not vs:continue
  lo,hi=va&~4095,(va+vs+4095)&~4095;u.mem_map(lo,hi-lo)
  if fl:u.mem_write(va,b[fo:fo+fl])
 return u,sy
for opt in (0,2,3):
 obj,lib=out/f'O{opt}.o',out/f'O{opt}.dylib'
 for cmd in [['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-c',str(source),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-no_fixup_chains','-dylib',str(obj),'-o',str(lib)]]:
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});write(out/'BUILD.json',build);assert not r.returncode,r.stderr
 u,sy=load(lib.read_bytes());engines.append((u,sy['_mobilelogic_png_chunk_prefix']));modules.append({'opt':opt,'sha256':sha(lib.read_bytes())})
r=subprocess.run(['clang-18','-target','arm64-apple-ios17.0','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-DCHUNK_CANDIDATE','-c',str(source),'-o',str(out/'chunk-candidate-real-imports.o')],capture_output=True,text=True,timeout=60);assert not r.returncode,r.stderr
r=subprocess.run(['llvm-nm-18','--undefined-only',str(out/'chunk-candidate-real-imports.o')],capture_output=True,text=True,timeout=60);write(out/'CANDIDATE_IMPORTS.json',{'undefined':r.stdout,'callback_offset':'0xf0','whole_function_runtime_verified':False});assert '_crc32' in r.stdout and '_png_error' in r.stdout
ref,_=load(raw)
for u,_ in [(ref,0)]+engines:
 u.mem_map(MEM,SIZE);u.mem_map(STACK,0x8000);u.mem_map(STOP,4096);u.mem_map(OUTPUT,4096);u.mem_map(CALLBACK,4096)
ref.mem_write(0x15ce10,struct.pack('<Q',MEM+0x2800))
covered=set();state={}
def hook(u,pc,sz,_):
 if pc in (CALLBACK,0x46fcc):state['cut']=pc;u.emu_stop();return
 assert 0x37c88<=pc<0x37e8c,hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
preserved=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
rng=random.Random(0x37c88);cases=16384;passes=[0,0,0];failures=[];outcomes={}
def text(u,p):return bytes(u.mem_read(p,64)).split(b'\0')[0]
for case in range(cases):
 mode=case%4;ctx=0 if mode==0 else MEM+128+(case&15);data=bytearray(rng.randbytes(SIZE));tag=rng.getrandbits(32)
 length=([0,1,0x7ffffffe,0x7fffffff][(case//4)%4] if mode!=1 else [0x80000000,0x100000000,0xffffffffffffffff][(case//4)%3])
 if ctx:struct.pack_into('<Q',data,ctx-MEM+0xf0,0 if mode==2 else CALLBACK)
 initial=[rng.getrandbits(64) for _ in preserved];fpcr,fpsr=(case%4)<<22,(case*0x01010101)&0xf800009f
 for ix,(u,entry) in enumerate([(ref,0x37c88)]+engines):
  u.mem_write(MEM,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x8000);u.mem_write(OUTPUT,bytes(4096))
  for r,v in zip(preserved,initial):u.reg_write(r,v)
  u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,STOP)
  for i,v in enumerate([ctx,tag,MEM+0x1000,length,OUTPUT]):u.reg_write(getattr(ac,f'UC_ARM64_REG_X{i}'),v)
  u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr);state['cut']=None;u.emu_start(entry,STOP,count=20000)
  if not ix:
   pc=state['cut']
   if pc is None:assert u.reg_read(ac.UC_ARM64_REG_PC)==STOP;observable=(0,0,0,0,b'')
   elif pc==0x46fcc:observable=(1,pc,u.reg_read(ac.UC_ARM64_REG_X0),0,text(u,u.reg_read(ac.UC_ARM64_REG_X1)))
   else:observable=(2,pc,u.reg_read(ac.UC_ARM64_REG_X0),u.reg_read(ac.UC_ARM64_REG_X2),bytes(u.mem_read(u.reg_read(ac.UC_ARM64_REG_X1),8)))
  else:
   kind,target,arg0,arg1=struct.unpack('<4Q',bytes(u.mem_read(OUTPUT,32)));observable=(kind,target,arg0,0 if kind==1 else arg1,text(u,arg1) if kind==1 else bytes(u.mem_read(OUTPUT+64,8)) if kind==2 else b'')
  actual=(observable,bytes(u.mem_read(MEM,SIZE)),u.reg_read(ac.UC_ARM64_REG_FPCR),u.reg_read(ac.UC_ARM64_REG_FPSR))
  if not ix:expected=actual;outcomes[mode]=outcomes.get(mode,0)+1
  else:
   ok=actual==expected and u.reg_read(ac.UC_ARM64_REG_PC)==STOP and u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x4000 and [u.reg_read(r) for r in preserved]==initial;passes[ix-1]+=int(ok)
   if not ok and len(failures)<8:failures.append({'case':case,'opt':(0,2,3)[ix-1],'expected':str(expected[0]),'actual':str(actual[0])})
report={'image_sha256':sha(raw),'entry':'0x37c88','end_exclusive':'0x37e8c','original_bytes':516,'original_function_sha256':sha(read(0x37c88,516)),'source_sha256':sha(source.read_bytes()),'cases':cases,'comparisons':cases*3,'passes':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'modules':modules,'original_instruction_locations':sorted(map(hex,covered)),'whole_function_verified':False,'native_stubs_used':False,'candidate_preserves_real_imports':['crc32','png_error'],'limits':['Null-context return or entry to actual length/null-write error helper or write callback. Callees unexecuted.','Full source candidate is object-build evidence only beyond the tested entry paths.','Actual callback, CRC32, error/abort, footer and caller integration require further original-byte testing.','No strict complete-function coverage increment, no framework or Payload replacement.']}
write(out/'REPORT.json',report);print(json.dumps(report,indent=2));assert not failures and passes==[cases]*3
