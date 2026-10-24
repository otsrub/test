"""New source recovery for MACore zstream-error and real claim call boundaries.
Instruction bytes remain original; encoded local table pointers receive real
DYLD_CHAINED_PTR_64_OFFSET rebase semantics. No imported callee is simulated.
"""
import argparse,hashlib,json,pathlib,random,struct,subprocess
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
ap=argparse.ArgumentParser();ap.add_argument('--mode',choices=['mapper','claim'],required=True);mode=ap.parse_args().mode
parent=pathlib.Path('prior/dependency-closure-dossier');raw=(parent/'MACore.original').read_bytes()
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(raw)=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
segs,sects,starts,symbols=macho(raw)
def read(a,n):
 for _,va,sz,fo,_ in sects:
  if va<=a and a+n<=va+sz:return raw[fo+a-va:fo+a-va+n]
 raise ValueError(hex(a))
o=32;formats=[]
for _ in range(struct.unpack_from('<I',raw,16)[0]):
 c,n=struct.unpack_from('<II',raw,o)
 if c==0x80000034:
  off,_=struct.unpack_from('<II',raw,o+8);h=struct.unpack_from('<7I',raw,off);ss=off+h[1];cnt=struct.unpack_from('<I',raw,ss)[0]
  for i,s in enumerate(struct.unpack_from('<'+'I'*cnt,raw,ss+4)):
   if s:
    _,page,fmt,segment_offset,_,_=struct.unpack_from('<IHHQIH',raw,ss+s);formats.append((segment_offset,fmt))
 o+=n
assert (0x178000,6) in formats,formats
encoded=struct.unpack('<10Q',read(0x15fd60,80))
def rebase(v):
 assert not (v>>63),hex(v)
 return (v&((1<<36)-1))|(((v>>36)&255)<<56)
table=list(map(rebase,encoded));assert all(0x110000<a<0x150000 for a in table)
literal_addresses=sorted(set(table+[0x12521e,0x1264d8,0x1264e7,0x12de59]))
def cstr(a):return read(a,256).split(b'\0')[0]
literals={a:cstr(a) for a in literal_addresses}
out=pathlib.Path('dependency-'+mode);out.mkdir(exist_ok=True)
write(out/'ORIGINAL_LITERAL_REBASE.json',{'pointer_format':6,'encoded':list(map(hex,encoded)),'rebased':list(map(hex,table)),'strings':{hex(a):b.decode() for a,b in literals.items()},'note':'Original data pointers rebased as image loaded at0. No original instruction changes.'})
header='\n'.join('static const char literal_%x[]={%s,0};'%(a,','.join(map(str,b))) for a,b in literals.items())+'\n'
header+='static const char *const error_table[10]={'+','.join('literal_%x'%a for a in table)+'};\n'
header+='static const unsigned char warning_constant[12]={'+','.join(map(str,read(0x11be58,12)))+'};\n'
common='''typedef unsigned long long u64; typedef unsigned int u32;
static u32 r32(const unsigned char *p){u32 v=0;for(unsigned i=0;i<4;i++)v|=(u32)p[i]<<(8*i);return v;}
static u64 r64(const unsigned char *p){u64 v=0;for(unsigned i=0;i<8;i++)v|=(u64)p[i]<<(8*i);return v;}
static void w32(unsigned char *p,u32 v){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i));}
static void w64(unsigned char *p,u64 v){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));}
'''
mapper='''/* Complete original MACore0x2dd78..0x2ddb4, retaining existing message. */
unsigned char *mobilelogic_png_zstream_error(unsigned char *ctx,u32 code){
 if(!r64(ctx+0x168)) {u32 index=code+7U;w64(ctx+0x168,(u64)(index<=9?error_table[index]:literal_12521e));}
 return ctx;
}
'''
claim='''/* Parameters selected from actual original bytes, not a replacement zlib. */
static void parameters(const unsigned char *c,u32 owner,u64 length,u32 p[5]){
 unsigned base=owner==0x49444154U?0x1b4:0x1c8;
 for(unsigned i=0;i<4;i++)p[i]=r32(c+base+4*i);
 if(owner!=0x49444154U)p[4]=r32(c+0x1d8);
 else p[4]=(r32(c+0x128)&1)?r32(c+0x1c4):(c[0x25e]!=8);
 if(length<=16384){u32 window=1U<<((p[2]-1U)&31U);u64 needed=length+262;
  if(needed<=(u64)window){do{window>>=1;p[2]--;}while(window>=(u32)needed);}
 }
}
/* Descriptor at first REAL call; no warning/zlib callbacks run here.
 result[0]kind,[1]target,[2..9]actual ABI arguments; warning bytes at+80.
 */
void mobilelogic_png_claim_prefix(unsigned char *c,u32 owner,u64 length,u64 *result){
 for(unsigned i=0;i<10;i++)result[i]=0;
 u32 busy=r32(c+0x130);
 if(busy){result[0]=0;result[1]=0x47204;result[2]=(u64)c;
  unsigned char *s=(unsigned char*)result+80;
  for(unsigned i=0;i<4;i++){s[i]=(unsigned char)(owner>>(24-8*i));s[6+i]=(unsigned char)(busy>>(24-8*i));}
  s[4]=':';s[5]=' ';for(unsigned i=0;i<12;i++)s[10+i]=warning_constant[i];s[22]='a';s[23]='m';s[24]=0;return;
 }
 u32 p[5];parameters(c,owner,length,p);u32 flags=r32(c+0x128);
 if(flags&2){unsigned equal=1;for(unsigned i=0;i<5;i++)if(r32(c+0x1dc+4*i)!=p[i])equal=0;
  if(!equal){result[0]=1;result[1]=0x104a88;result[2]=(u64)(c+0x138);return;}
 }
 w64(c+0x138,0);w32(c+0x140,0);w64(c+0x150,0);w32(c+0x158,0);
 result[2]=(u64)(c+0x138);
 if(flags&2){result[0]=2;result[1]=0x104aac;}
 else{result[0]=3;result[1]=0x104a94;for(unsigned i=0;i<5;i++)result[3+i]=p[i];result[8]=(u64)literal_12de59;result[9]=0x70;}
}
#ifdef CLAIM_CANDIDATE
extern int deflateEnd(void*);
extern int deflateReset(void*);
extern int deflateInit2_(void*,int,int,int,int,int,const char*,int);
extern void png_warning(void*,const char*);
int mobilelogic_png_claim_candidate(unsigned char *c,u32 owner,u64 length){
 u32 busy=r32(c+0x130);
 if(busy){char s[25];for(unsigned i=0;i<4;i++){s[i]=(char)(owner>>(24-8*i));s[6+i]=(char)(busy>>(24-8*i));}
  s[4]=':';s[5]=' ';for(unsigned i=0;i<12;i++)s[10+i]=(char)warning_constant[i];s[22]='a';s[23]='m';s[24]=0;
  png_warning(c,s);if(r32(c+0x130)==0x49444154U){w64(c+0x168,(u64)literal_1264d8);return -2;}w32(c+0x130,0);
 }
 u32 p[5];parameters(c,owner,length,p);u32 flags=r32(c+0x128);
 if(flags&2){unsigned equal=1;for(unsigned i=0;i<5;i++)if(r32(c+0x1dc+4*i)!=p[i])equal=0;
  if(!equal){if(deflateEnd(c+0x138))png_warning(c,literal_1264e7);flags=r32(c+0x128)&~2U;w32(c+0x128,flags);}
 }
 w64(c+0x138,0);w32(c+0x140,0);w64(c+0x150,0);w32(c+0x158,0);
 int status;
 if(flags&2)status=deflateReset(c+0x138);
 else{status=deflateInit2_(c+0x138,(int)p[0],(int)p[1],(int)p[2],(int)p[3],(int)p[4],literal_12de59,112);
  if(!status)w32(c+0x128,r32(c+0x128)|2U);}
 if(!status)w32(c+0x130,owner);else mobilelogic_png_zstream_error(c,(u32)status);
 return status;
}
#endif
'''
source=out/('macore_png_zstream_error.c' if mode=='mapper' else 'macore_png_claim.c')
source.write_text(common+header+mapper+(claim if mode=='claim' else ''))
entry=0x2dd78 if mode=='mapper' else 0x38aa4;end=0x2ddb4 if mode=='mapper' else 0x38d48
assert sha(read(entry,end-entry))==('1ee01b5d442c15a458e86266bf81453933930fae315b9f54c9f5f3e2e4b05736' if mode=='mapper' else 'd2bcab9fb348eb6fc8fba5179bda40564143948653385461177a07fe0103a4e0')
(source.parent/'Makefile').write_text('CC = clang-18\nLD = ld64.lld-18\nall: module.dylib\nmodule.o: '+source.name+'\n\t$(CC) -target arm64-apple-ios17.0 -O2 -ffreestanding -fno-builtin -fno-stack-protector -c $< -o $@\nmodule.dylib: module.o\n\t$(LD) -arch arm64 -platform_version ios 17.0 17.0 -no_fixup_chains -dylib $< -o $@\n')
MEM,STACK,STOP,OUTPUT=0x30000000,0x40000000,0x50000000,0x60000000
SIZE=0x3000
build=[];modules=[];engines=[]
def map_image(b):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);sg,_,_,sy=macho(b)
 for name,va,vs,fo,fl in sg:
  if name=='__PAGEZERO' or not vs:continue
  lo,hi=va&~4095,(va+vs+4095)&~4095;u.mem_map(lo,hi-lo)
  if fl:u.mem_write(va,b[fo:fo+fl])
 return u,sy
for opt in (0,2,3):
 obj,lib=out/f'O{opt}.o',out/f'O{opt}.dylib'
 for cmd in [['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-Wno-unused-function','-Wno-unused-const-variable','-c',str(source),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-no_fixup_chains','-dylib',str(obj),'-o',str(lib)]]:
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});write(out/'BUILD.json',build);assert not r.returncode,r.stderr
 b=lib.read_bytes();u,sy=map_image(b);engines.append((u,sy['_mobilelogic_png_zstream_error' if mode=='mapper' else '_mobilelogic_png_claim_prefix']));modules.append({'optimization':opt,'sha256':sha(b)})
if mode=='claim':
 cmd=['clang-18','-target','arm64-apple-ios17.0','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-DCLAIM_CANDIDATE','-c',str(source),'-o',str(out/'claim-candidate-real-imports.o')]
 r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);assert not r.returncode,r.stderr
 r=subprocess.run(['llvm-nm-18','--undefined-only',str(out/'claim-candidate-real-imports.o')],capture_output=True,text=True,timeout=60)
 write(out/'CANDIDATE_IMPORTS.json',{'undefined':r.stdout,'status':'Object build only; actual imported bodies and runtime callback effects unverified.'})
 for name in ['_deflateEnd','_deflateReset','_deflateInit2_','_png_warning']:assert name in r.stdout
ref,_=map_image(raw);ref.mem_write(0x15fd60,struct.pack('<10Q',*table))
for u,_ in [(ref,entry)]+engines:
 u.mem_map(MEM,SIZE);u.mem_map(STACK,0x8000);u.mem_map(STOP,4096);u.mem_map(OUTPUT,4096)
ref.mem_write(0x15ce10,struct.pack('<Q',MEM+0x2800))
covered=set();state={};targets={0x47204:0,0x104a88:1,0x104aac:2,0x104a94:3}
def hook(u,pc,size,_):
 if mode=='claim' and pc in targets:state['cut']=pc;u.emu_stop();return
 assert entry<=pc<end,hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
preserved=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
rng=random.Random(entry);cases=16384;passes=[0,0,0];failures=[];outcomes={}
def string(u,a):
 return bytes(u.mem_read(a,128)).split(b'\0')[0]
for case in range(cases):
 ctx=MEM+128+(case&15);data=bytearray(rng.randbytes(SIZE));code=([0xffffffff,0xfffffff8,0xfffffff9,0xfffffffA,0xfffffffB,0xfffffffC,0xfffffffD,0xfffffffE,0,1,2,3,0x7fffffff,0x80000000][case%14] if case<8192 else rng.getrandbits(32))
 owner=rng.choice([0x49444154,0,1,0xffffffff]);length=([0,1,255,256,257,16383,16384,16385,0xffffffffffffffff][case%9] if case<8192 else rng.getrandbits(64))
 prior=0 if case%3 else rng.getrandbits(64)
 struct.pack_into('<Q',data,ctx-MEM+0x168,prior)
 if mode=='claim':
  path=case%4;struct.pack_into('<I',data,ctx-MEM+0x130,rng.getrandbits(32) or 1 if path==0 else 0)
  flags=rng.getrandbits(32);flags=(flags|2) if path in (1,2) else (flags&~2);struct.pack_into('<I',data,ctx-MEM+0x128,flags)
  p=[rng.getrandbits(32) if case%5==0 else rng.randrange(4,17) for _ in range(5)]
  for base in (0x1b4,0x1c8):
   for i,v in enumerate(p[:4]):struct.pack_into('<I',data,ctx-MEM+base+4*i,v)
  struct.pack_into('<I',data,ctx-MEM+0x1c4,p[4]);struct.pack_into('<I',data,ctx-MEM+0x1d8,p[4]);data[ctx-MEM+0x25e]=8 if case&1 else 16
  strategy=p[4] if owner!=0x49444154 or flags&1 else int(data[ctx-MEM+0x25e]!=8)
  win=p[2]
  if length<=16384:
   w=1<<((win-1)&31);needed=length+262
   if needed<=w:
    while True:
     w>>=1;win=(win-1)&0xffffffff
     if w<needed:break
  selected=p[:2]+[win,p[3],strategy]
  for i,v in enumerate(selected):struct.pack_into('<I',data,ctx-MEM+0x1dc+4*i,v if path==2 else v^0x11223344)
 initial=[rng.getrandbits(64) for _ in preserved];fpcr,fpsr=(case%4)<<22,(case*0x01010101)&0xf800009f
 for ix,(u,e) in enumerate([(ref,entry)]+engines):
  u.mem_write(MEM,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x8000);u.mem_write(OUTPUT,bytes(4096))
  for r,v in zip(preserved,initial):u.reg_write(r,v)
  u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,STOP)
  for r,v in zip([ac.UC_ARM64_REG_X0,ac.UC_ARM64_REG_X1,ac.UC_ARM64_REG_X2,ac.UC_ARM64_REG_X3],[ctx,code if mode=='mapper' else owner,length,OUTPUT]):u.reg_write(r,v)
  u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr);state['cut']=None;u.emu_start(e,STOP,count=20000)
  memory=bytearray(u.mem_read(MEM,SIZE));reg=(u.reg_read(ac.UC_ARM64_REG_FPCR),u.reg_read(ac.UC_ARM64_REG_FPSR))
  if mode=='mapper':
   value=struct.unpack_from('<Q',memory,ctx-MEM+0x168)[0]
   if prior:observable=('retained',value)
   else:observable=('selected',string(u,value));memory[ctx-MEM+0x168:ctx-MEM+0x170]=bytes(8)
   observable=(observable,u.reg_read(ac.UC_ARM64_REG_X0))
  elif not ix:
   pc=state['cut'];assert pc in targets;kind=targets[pc];args=[0]*8;args[0]=u.reg_read(ac.UC_ARM64_REG_X0)
   warning=b''
   if kind==0:warning=bytes(u.mem_read(u.reg_read(ac.UC_ARM64_REG_X1),25))
   if kind==3:
    for i in range(1,6):args[i]=u.reg_read(getattr(ac,f'UC_ARM64_REG_X{i}'))
    args[6]=0;args[7]=u.reg_read(ac.UC_ARM64_REG_X7)
    assert string(u,u.reg_read(ac.UC_ARM64_REG_X6))==b'1.2.12'
   observable=(kind,pc,args,warning)
  else:
   descriptor=list(struct.unpack('<10Q',bytes(u.mem_read(OUTPUT,80))));kind=descriptor[0];args=descriptor[2:10];warning=bytes(u.mem_read(OUTPUT+80,25)) if kind==0 else b''
   if kind==3:assert string(u,args[6])==b'1.2.12';args[6]=0
   observable=(kind,descriptor[1],args,warning)
  actual=(observable,bytes(memory),reg)
  if not ix:expected=actual;outcomes[str(observable[0])]=outcomes.get(str(observable[0]),0)+1
  else:
   ok=actual==expected and u.reg_read(ac.UC_ARM64_REG_PC)==STOP and [u.reg_read(r) for r in preserved]==initial and u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x4000
   passes[ix-1]+=int(ok)
   if not ok and len(failures)<8:failures.append({'case':case,'optimization':(0,2,3)[ix-1],'expected':str(expected[0]),'actual':str(actual[0]),'memory_equal':actual[1]==expected[1],'fp_equal':actual[2]==expected[2]})
report={'image_sha256':sha(raw),'entry':hex(entry),'end_exclusive':hex(end),'original_bytes':end-entry,'original_function_sha256':sha(read(entry,end-entry)),'source_sha256':sha(source.read_bytes()),'cases':cases,'comparisons':cases*3,'passes':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'modules':modules,'original_instruction_locations':sorted(map(hex,covered)),'whole_function_bounded_test':mode=='mapper','native_stubs_used':False,'native_callees_executed':False,'limits':['Finite stable allocated memory, not all-input proof.','Source-built string addresses normalized by exact string content; existing pointers preserved.','Claim mode tests first actual native call boundary only; imported bodies/callback continuation unexecuted.','Private compiler stack differs; candidate return ABI, preserved registers/SP/FP state checked.','Whole native image and Payload replacement remain open.']}
write(out/'REPORT.json',report);print(json.dumps(report,indent=2));assert passes==[cases]*3 and not failures
