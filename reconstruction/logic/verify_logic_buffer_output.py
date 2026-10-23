"""Actual callable source ABI; real original helper execution; cuts before unresolved externals."""
import pathlib,struct,json,random,subprocess,os,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
LANE=os.environ['REA_LANE'];assert LANE in ['padding','string'];OUT=ROOT/('buffer-output-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=(ROOT/'reconstruction/logic/logic_buffer_output_candidate.c').read_text();(OUT/'logic_buffer_output_candidate.c').write_text(SOURCE)
def metadata(b):
 pos=32;sections=[];ind=None;sym=None;stream=None;base=None
 for _ in range(struct.unpack_from('<I',b,16)[0]):
  cmd,n=struct.unpack_from('<II',b,pos)
  if cmd==2:sym=struct.unpack_from('<IIII',b,pos+8)
  if cmd==11:ind=struct.unpack_from('<II',b,pos+56)
  if cmd==0x26:
   off,size=struct.unpack_from('<II',b,pos+8);stream=b[off:off+size]
  if cmd==25:
   if b[pos+8:pos+24].split(b'\0')[0]==b'__TEXT':base=struct.unpack_from('<Q',b,pos+24)[0]
   for j in range(struct.unpack_from('<I',b,pos+64)[0]):
    at=pos+72+j*80;va,size=struct.unpack_from('<QQ',b,at+32);flags,ri,stride=struct.unpack_from('<III',b,at+64)
    if flags&255==8:sections.append((va,size,ri,stride))
  pos+=n
 imports={};starts=[]
 if ind and sym:
  so,count,st,sz=sym
  for va,size,ri,stride in sections:
   for j in range(size//stride):
    idx=struct.unpack_from('<I',b,ind[0]+4*(ri+j))[0]
    if idx&0xc0000000:continue
    si=struct.unpack_from('<I',b,so+16*idx)[0];name=b[st+si:b.index(b'\0',st+si)].decode();imports[va+j*stride]=name
 if stream is not None:
  a=base;v=shift=0
  for byte in stream:
   v|=(byte&127)<<shift
   if byte&128:shift+=7;continue
   if not v:break
   a+=v;starts.append(a);v=shift=0
 return imports,starts
im,starts=metadata(original);assert {a:im[a] for a in [0xf0bfe8,0xf0bff4,0xf0c000]}=={0xf0bfe8:'_memcpy',0xf0bff4:'_memmove',0xf0c000:'_memset'}
for a,b in [(0x8b86dc,0x8b88d0),(0x8b8b0c,0x8b8cd0)]:assert starts[starts.index(a)+1]==b
engines=[];diags=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-fno-stack-protector","-Wall","-Wextra","-Werror","-c",str(OUT/'logic_buffer_output_candidate.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','dynamic_lookup',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);entry=next(v for n,v,undefined in syms if n==('_logic_buffer_padding' if LANE=='padding' else '_logic_buffer_string') and not undefined);im,_=metadata(raw)
 assert set(im.values())<={'_memcpy','_memmove','_memset'},im
 st={};blr={}
 for vm,vs,off,fs in macho(raw)[0]:
  for at in range(off,off+fs-3,4):
   word=struct.unpack_from('<I',raw,at)[0]
   if word&0xfffffc1f==0xd63f0000:blr[vm+at-off]=(word>>5)&31
 st['blr']=blr
 def compiled_hook(u,pc,n,st):
  if pc in st['imports']:
   name=st['imports'][pc];st['cut']=name[1:];u.emu_stop();return
  if pc in st['blr']:
   rn=st['blr'][pc];st['growth_target']=u.reg_read(globals()[f'UC_ARM64_REG_X{rn}']);st['cut']='grow';u.emu_stop()
 st['imports']=im;u.hook_add(UC_HOOK_CODE,compiled_hook,st);engines.append((u,entry,sha(raw),st))

ref,_=engine(original);state={};covered=set();calls={};grows={0x8b87b4,0x8b889c,0x8b8bdc,0x8b8c9c}
def ref_hook(u,pc,n,_):
 if pc in [0xf0bfe8,0xf0bff4,0xf0c000]:state['cut']={0xf0bfe8:'memcpy',0xf0bff4:'memmove',0xf0c000:'memset'}[pc];u.emu_stop();return
 if pc in grows:state['cut']='grow';state['growth_target']=u.reg_read(UC_ARM64_REG_X8);u.emu_stop();return
 assert 0x8b86dc<=pc<0x8b88d0 or 0x8b8b0c<=pc<0x8b8cd0,hex(pc);covered.add(pc)
 if pc==0x8b8b0c:calls['padding']=calls.get('padding',0)+1
ref.hook_add(UC_HOOK_CODE,ref_hook)
regs=list(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))+[UC_ARM64_REG_X29]+[UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
rng=random.Random(0x8b86dc+len(LANE));passes=[0,0,0];failures=[];cases=16384;outcomes={};fills=[0,32,46,0x0302017f,0x12345680,0x030201bf,0xa2c2,0xac82e2,0x80989ff0,0xffffffF7]
def observed(u,st):
 kind=st.get('cut','return');a=[u.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2]]
 if kind=='return':return (kind,a[:1])
 if kind=='grow':return (kind,[st['growth_target']]+a[:2])
 if kind=='memcpy':
  assert STACK<=a[1]<STACK+0x4000 and 0<a[2]<=4
  return (kind,[a[0],bytes(u.mem_read(a[1],a[2])).hex(),a[2]])
 if kind=='memset':a[1]&=0xffffffff
 return (kind,a)
start=0x8b8b0c if LANE=='padding' else 0x8b86dc
for case in range(cases):
 data=bytearray(rng.randbytes(0x3000));out=BASE+0x100+case%16;limit=BASE+0x300+(case//16)%16;text=BASE+0x1000+case%16;buf=BASE+0x1800;callback=0x5000000+(case%16)*4
 cap=[0,1,2,4,8,16,32,64,96][case%9];pos=rng.randrange(cap+1);count=rng.randrange(33);size=rng.randrange(65);visual=rng.randrange(65);fill=fills[(case//9)%len(fills)];width=rng.randrange(-16,65)
 end=rng.randrange(65);used=rng.choice([0,end,max(0,end-1),end+1,0xffffffffffffffff,rng.randrange(73)])
 struct.pack_into('<QQQQQ',data,out-BASE,buf,cap,pos,callback,limit if case%3 else 0);struct.pack_into('<QQ',data,limit-BASE,end,used)
 first=((width&0xffffffff)<<32)|rng.getrandbits(32);second=(fill<<32)|rng.getrandbits(32)
 args=[out,count,fill] if LANE=='padding' else [text,size,out,first,second,visual]
 saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x3000;fpsr=case%4;fpcr=((case//4)%4)<<22
 def initialize(u):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x4000)
  for r,v in zip(regs,saved):u.reg_write(r,v)
  for r,v in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5],args):u.reg_write(r,v)
  for r,v in [(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,v)
 initialize(ref);state.clear();ref.emu_start(start,STOP,count=10000);wanted=observed(ref,state);memory=bytes(ref.mem_read(BASE,len(data)))
 if wanted[0]=='return':assert ref.reg_read(UC_ARM64_REG_PC)==STOP and ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
 for oi,(u,entry,_,st) in enumerate(engines):
  initialize(u);st.pop('cut',None);st.pop('growth_target',None);u.emu_start(entry,STOP,count=30000);got=observed(u,st)
  ok=got==wanted and bytes(u.mem_read(BASE,len(data)))==memory and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR) and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR)
  if got[0]=='return':ok=ok and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved
  passes[oi]+=int(ok)
  if not ok and len(failures)<25:failures.append({'case':case,'capacity':cap,'position':pos,'count':count,'size':size,'visual':visual,'width':width,'fill':hex(fill),'limit_end':end,'limit_used':used,'has_limit':case%3!=0,'opt':[0,2,3][oi],'expected':wanted,'actual':got,'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory})
 outcomes[wanted[0]]=outcomes.get(wanted[0],0)+1
report={'image_sha256':sha(original),'entry':hex(start),'lane':LANE,'cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'actual_original_helper_calls':calls,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[e[2] for e in engines],'actual_function_ABI_source':True,'whole_function_verified':False,'all_input_equivalence_proven':False,'limits':['Original entry-to-return or exact entry to real memcpy/memmove/memset; indirect growth calls stop BEFORE BLR in both images. No callback implementation installed or executed.','String lane executes actual original padding helper bytes. Compare all modeled buffer/limit/input memory, return ABI or call target/arguments, callee-saved state/SP on returns and FPCR/FPSR.','For memcpy from the private fill object, compare source byte contents and length after checking stack bounds; private stack pointer addresses are implementation-dependent. memset uses int-width argument normalization. No public pointers normalized.','Ordinary disjoint mapped storage; capacity/position 0..96 with position<=capacity; counts<=32; string/visual length<=64; width -16..64; fill leading-byte lengths 0..4. Limit counters exercise unsigned wrap. Larger/invalid fill, real library/callback behavior, faults, aliases, MMIO, concurrency and all-input equivalence remain unresolved.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
