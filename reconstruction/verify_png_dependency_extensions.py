"""New PNG primitive whole-function candidates and actual warning composition."""
import argparse,hashlib,json,pathlib,random,struct,subprocess
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
p=argparse.ArgumentParser();p.add_argument('--mode',choices=['bits','warning'],required=True);mode=p.parse_args().mode
raw=pathlib.Path('prior/dependency-closure-dossier/MACore.original').read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(raw)=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
sg,sc,starts,sy=macho(raw)
def read(a,n):
 for _,v,s,o,_ in sc:
  if v<=a and a+n<=v+s:return raw[o+a-v:o+a-v+n]
 raise ValueError(hex(a))
out=pathlib.Path('png-extension-'+mode);out.mkdir(exist_ok=True)
bits='''typedef unsigned int u32;
static u32 be32(const unsigned char*p){return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3];}
u32 mobilelogic_png_get_int32(const unsigned char*p){u32 n=be32(p);return n==0x80000000U?0:n;}
u32 mobilelogic_png_get_uint32(const unsigned char*p){return be32(p);}
u32 mobilelogic_png_get_uint16(const unsigned char*p){return ((u32)p[0]<<8)|p[1];}
unsigned char *mobilelogic_png_save_uint32(unsigned char*p,u32 n){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(24-i*8));return p;}
unsigned char *mobilelogic_png_save_int32(unsigned char*p,u32 n){return mobilelogic_png_save_uint32(p,n);}
unsigned char *mobilelogic_png_save_uint16(unsigned char*p,u32 n){p[0]=(unsigned char)(n>>8);p[1]=(unsigned char)n;return p;}
'''
warning='''/* Actual warning helper0x47204..0x47390 to its real next callee.
 * Optional full source candidate retains actual callbacks and stdio imports.
 */
#include "macore_png_claim.c"
static const char warning_format[]="libpng warning: %s";
static const unsigned char *warning_message(unsigned char*c,const unsigned char*m){
 if(c && m[0]=='#'){unsigned i=1;while(i<15 && m[i]!=' ')i++;return m+i;}return m;
}
void mobilelogic_png_warning_boundary(unsigned char*c,const unsigned char*m,u64*out,u64 file){
 m=warning_message(c,m);u64 callback=c?r64(c+0xe0):0;
 out[0]=callback?callback:0x104be4;out[1]=callback?(u64)c:file;
 out[2]=callback?0:(u64)warning_format;out[3]=(u64)m;
}
void mobilelogic_png_claim_warning_composed(unsigned char*c,u32 owner,u64*out,u64 file){
 u64 first[16];mobilelogic_png_claim_prefix(c,owner,0,first);
 const unsigned char*m=(const unsigned char*)first+80;
 mobilelogic_png_warning_boundary(c,m,out,file);
 unsigned char*copy=(unsigned char*)out+64;for(unsigned i=0;i<25;i++)copy[i]=m[i];
 out[3]=(u64)copy+(out[3]-(u64)m);
}
#ifdef WARNING_CANDIDATE
extern void *__stderrp;
extern int fprintf(void*,const char*,...);
extern int fputc(int,void*);
void mobilelogic_png_warning_candidate(unsigned char*c,const unsigned char*m){
 m=warning_message(c,m);u64 callback=c?r64(c+0xe0):0;
 if(callback)((void(*)(void*,const unsigned char*))callback)(c,m);
 else{fprintf(__stderrp,warning_format,m);fputc(10,__stderrp);}
}
#endif
'''
source=out/('macore_png_integer_primitives.c' if mode=='bits' else 'macore_png_warning.c');source.write_text(bits if mode=='bits' else warning)
if mode=='warning':
 parent=pathlib.Path('claim-parent/dependency-claim/macore_png_claim.c');(out/parent.name).write_bytes(parent.read_bytes())
entries=[(0xafeb0,52,'mobilelogic_png_get_int32'),(0xafea4,12,'mobilelogic_png_get_uint32'),(0xafee4,16,'mobilelogic_png_get_uint16'),(0x37970,12,'mobilelogic_png_save_uint32'),(0x2d46c,12,'mobilelogic_png_save_int32'),(0x3797c,16,'mobilelogic_png_save_uint16')] if mode=='bits' else [(0x47204,396,'mobilelogic_png_warning_boundary'),(0x38aa4,676,'mobilelogic_png_claim_warning_composed')]
for a,n,_ in entries:assert a in starts and starts[starts.index(a)+1]==a+n
MEM,STACK,STOP,OUTPUT,CALLBACK,FILE=0x30000000,0x40000000,0x50000000,0x60000000,0x70000000,0x70002000
SIZE=0x3000
build=[];modules=[];engines=[]
def load(b):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);seg,_,_,sym=macho(b)
 for name,va,vs,fo,fl in seg:
  if name=='__PAGEZERO' or not vs:continue
  low,high=va&~4095,(va+vs+4095)&~4095;u.mem_map(low,high-low)
  if fl:u.mem_write(va,b[fo:fo+fl])
 return u,sym
for opt in (0,2,3):
 obj,lib=out/f'O{opt}.o',out/f'O{opt}.dylib'
 for cmd in [['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-c',str(source),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-no_fixup_chains','-dylib',str(obj),'-o',str(lib)]]:
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});write(out/'BUILD.json',build);assert r.returncode==0,r.stderr
 u,sym=load(lib.read_bytes());engines.append((u,sym));modules.append({'optimization':opt,'sha256':sha(lib.read_bytes())})
if mode=='warning':
 obj=out/'warning-candidate-real-imports.o';r=subprocess.run(['clang-18','-target','arm64-apple-ios17.0','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-DWARNING_CANDIDATE','-c',str(source),'-o',str(obj)],capture_output=True,text=True,timeout=60);assert not r.returncode,r.stderr
 r=subprocess.run(['llvm-nm-18','--undefined-only',str(obj)],capture_output=True,text=True,timeout=60);write(out/'CANDIDATE_IMPORTS.json',{'undefined':r.stdout,'callback_offset':'0xe0','whole_function_runtime_verified':False});assert all(n in r.stdout for n in ['_fprintf','_fputc','___stderrp'])
ref,_=load(raw)
for u,_ in [(ref,{})]+engines:
 u.mem_map(MEM,SIZE);u.mem_map(STACK,0x8000);u.mem_map(STOP,4096);u.mem_map(OUTPUT,4096);u.mem_map(CALLBACK,0x3000)
ref.mem_write(0x15ce10,struct.pack('<Q',MEM+0x2800));ref.mem_write(0x15ce18,struct.pack('<Q',MEM+0x2808))
covered=set();state={};active=[entries[0][0]]
def hook(u,pc,sz,_):
 if mode=='warning' and pc in (CALLBACK,0x104be4):state['cut']=pc;u.emu_stop();return
 if mode=='warning':assert 0x47204<=pc<0x47390 or 0x38aa4<=pc<0x38d48,hex(pc)
 else:assert active[0]<=pc<active[0]+next(n for a,n,_ in entries if a==active[0]),hex(pc)
 covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
preserved=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
rng=random.Random(0x47390);cases=16384;passes=[0,0,0];failures=[];outcomes={};per_function=[]
def text(u,a):
 return bytes(u.mem_read(a,64)).split(b'\0')[0]
for entry,n,name in entries:
 active[0]=entry
 for case in range(cases):
  data=bytearray(rng.randbytes(SIZE));ctx=MEM+128+(case&15);message=MEM+0x1000+(case&15);ptr=MEM+0x1000+(case&31)
  value=([0,1,0x7fffffff,0x80000000,0x80000001,0xffffffff,0xffff,0x10000][case%8] if case<8192 else rng.getrandbits(32));struct.pack_into('>I',data,ptr-MEM,value)
  owner=0x23234344 if case&1 else rng.getrandbits(32)
  if mode=='warning':
   struct.pack_into('<Q',data,ctx-MEM+0xe0,CALLBACK if case&2 else 0);struct.pack_into('<I',data,ctx-MEM+0x130,rng.getrandbits(32) or 1)
   struct.pack_into('<Q',data,0x2808,FILE)
   msg=bytearray(b'#0123456789abcdef-message'+bytes(40));position=case%17
   if position<16:msg[position]=32
   if case%19==0:msg[0]=65
   data[message-MEM:message-MEM+len(msg)]=msg
   if entry==0x47204 and case%5==0:ctx=0
  initial=[rng.getrandbits(64) for _ in preserved];fpcr,fpsr=(case%4)<<22,(case*0x01010101)&0xf800009f
  for ix,(u,sym) in enumerate([(ref,{})]+engines):
   u.mem_write(MEM,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x8000);u.mem_write(OUTPUT,bytes(4096))
   for r,v in zip(preserved,initial):u.reg_write(r,v)
   u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,STOP)
   args=[ptr,value] if mode=='bits' else [ctx,message,OUTPUT,FILE] if entry==0x47204 else [ctx,owner,OUTPUT,FILE]
   for i,v in enumerate(args):u.reg_write(getattr(ac,f'UC_ARM64_REG_X{i}'),v)
   u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr);state['cut']=None
   u.emu_start(entry if not ix else sym['_'+name],STOP,count=20000)
   if mode=='bits':observable=u.reg_read(ac.UC_ARM64_REG_X0)
   elif not ix:
    target=state['cut'];assert target in (CALLBACK,0x104be4);arg0=u.reg_read(ac.UC_ARM64_REG_X0)
    if target==CALLBACK:m=u.reg_read(ac.UC_ARM64_REG_X1);fmt=b''
    else:m=struct.unpack('<Q',bytes(u.mem_read(u.reg_read(ac.UC_ARM64_REG_SP),8)))[0];fmt=text(u,u.reg_read(ac.UC_ARM64_REG_X1))
    observable=(target,arg0,fmt,text(u,m),m if entry==0x47204 else 0)
   else:
    target,arg0,fmt,m=struct.unpack('<4Q',bytes(u.mem_read(OUTPUT,32)));observable=(target,arg0,text(u,fmt) if fmt else b'',text(u,m),m if entry==0x47204 else 0)
   actual=(observable,bytes(u.mem_read(MEM,SIZE)),u.reg_read(ac.UC_ARM64_REG_FPCR),u.reg_read(ac.UC_ARM64_REG_FPSR))
   if not ix:expected=actual;outcomes[str(observable[0]) if mode=='warning' else name]=outcomes.get(str(observable[0]) if mode=='warning' else name,0)+1
   else:
    ok=actual==expected and u.reg_read(ac.UC_ARM64_REG_PC)==STOP and u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x4000 and [u.reg_read(r) for r in preserved]==initial
    passes[ix-1]+=int(ok)
    if not ok and len(failures)<8:failures.append({'entry':hex(entry),'case':case,'opt':(0,2,3)[ix-1],'expected':str(expected[0]),'actual':str(actual[0]),'memory_equal':expected[1]==actual[1]})
 per_function.append({'entry':hex(entry),'end_exclusive':hex(entry+n),'original_bytes':n,'original_function_sha256':sha(read(entry,n)),'name':name,'cases':cases,'comparisons':cases*3,'status':'complete_function_candidate' if mode=='bits' else 'actual_native_warning_call_boundary'})
report={'image_sha256':sha(raw),'mode':mode,'functions':per_function,'comparisons':cases*len(entries)*3,'passes':passes,'mismatches':cases*len(entries)*3-sum(passes),'failures':failures,'modules':modules,'source_sha256':sha(source.read_bytes()),'original_instruction_locations':sorted(map(hex,covered)),'outcomes':outcomes,'whole_function_candidates':len(entries) if mode=='bits' else 0,'native_stubs_used':False,'original_warning_body_executed':mode=='warning','actual_callback_or_stdio_executed':False,'limits':['Finite tests, not all-input proof.','Integer candidates require historical accepted-key reconciliation before aggregate count.','Warning tests execute actual original warning helper, stop at real callback or fprintf; no success callback/stdio simulation.','All public modeled memory, result/call arguments, preserved ABI/SP/FP state compared.','No whole image or Payload replacement.']}
write(out/'REPORT.json',report);print(json.dumps(report,indent=2));assert not failures and passes==[cases*len(entries)]*3
