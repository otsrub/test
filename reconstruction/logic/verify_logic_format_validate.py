"""Actual callable source ABI; real original helper execution; cuts before unresolved externals."""
import pathlib,struct,json,random,subprocess,os,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
OUT=ROOT/'format-validation';OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=(ROOT/'reconstruction/logic/logic_format_validate_candidate.c').read_text();(OUT/'logic_format_validate_candidate.c').write_text(SOURCE)
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
_,starts=metadata(original);assert starts[starts.index(0x8be83c)+1]==0x8be92c
engines=[];diags=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-fno-stack-protector","-Wall","-Wextra","-Werror","-c",str(OUT/'logic_format_validate_candidate.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','dynamic_lookup',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);entry=next(v for n,v,undefined in syms if n=='_logic_format_validate' and not undefined);im,_=metadata(raw)
 assert set(im.values())<={'_logic_flag_error_original_8bfc08','_logic_presentation_error_original_8b5ab0','_logic_format_error_original_8b4614'},im
 st={}
 def compiled_hook(u,pc,n,st):
  if pc in st['imports']:
   name=st['imports'][pc];st['cut']={'_logic_flag_error_original_8bfc08':'flag','_logic_presentation_error_original_8b5ab0':'presentation','_logic_format_error_original_8b4614':'error'}[name];u.emu_stop()
 st['imports']=im;u.hook_add(UC_HOOK_CODE,compiled_hook,st);engines.append((u,entry,sha(raw),st))

ref,_=engine(original);state={};covered=set();calls={}
def ref_hook(u,pc,n,_):
 if pc in [0x8b4614,0x8bfc08,0x8b5ab0]:state['cut']={0x8b4614:'error',0x8bfc08:'flag',0x8b5ab0:'presentation'}[pc];u.emu_stop();return
 assert 0x8be83c<=pc<0x8be92c,hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,ref_hook)
regs=list(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))+[UC_ARM64_REG_X29]+[UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
rng=random.Random(0x8be83c);passes=[0,0,0];cases=0;failures=[];outcomes={};families={}
def inputs():
 for flag in range(256):
  for mask in range(32):yield ('all-flags-and-capability-masks',flag,(flag*17+mask)%256,mask,0xffffffff if mask%2 else 0,rng.getrandbits(32))
 for typ in range(256):
  for mask in range(32):
   for flag in [0,4,8,0x18,0x20,0x40,0x7f,0xff]:yield ('all-type-bytes-and-error-precedence',flag,typ,mask,0xffffffff if flag%2 else 0,rng.choice([0,1,0xffffffff,rng.getrandbits(32)]))
 for _ in range(8192):yield ('random-precision-and-presentation-bitmaps',rng.randrange(256),rng.randrange(256),rng.getrandbits(32),rng.getrandbits(32),rng.getrandbits(32))
def observed(u,st):
 kind=st.get('cut','return')
 if kind=='return':return (kind,[])
 return (kind,[u.reg_read(r) for r in ([UC_ARM64_REG_X0,UC_ARM64_REG_X1] if kind=='flag' else [UC_ARM64_REG_X0])])
for case,(family,flag,typ,mask,precision,allowed) in enumerate(inputs()):
 data=bytearray(rng.randbytes(0x1000));spec=BASE+0x100+case%16;name=BASE+0x500+case%16;data[spec-BASE]=flag;data[spec-BASE+1]=typ;struct.pack_into('<I',data,spec-BASE+8,precision);data[name-BASE:name-BASE+5]=b'type\0'
 saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x3000;fpsr=case%4;fpcr=((case//4)%4)<<22
 def initialize(u):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x4000)
  for r,v in zip(regs,saved):u.reg_write(r,v)
  for r,v in [(UC_ARM64_REG_X0,spec),(UC_ARM64_REG_X1,mask),(UC_ARM64_REG_X2,name),(UC_ARM64_REG_X3,allowed),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,v)
 initialize(ref);state.clear();ref.emu_start(0x8be83c,STOP,count=300);wanted=observed(ref,state);assert bytes(ref.mem_read(BASE,len(data)))==bytes(data)
 if wanted[0]=='return':assert ref.reg_read(UC_ARM64_REG_PC)==STOP and ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
 for oi,(u,entry,_,st) in enumerate(engines):
  initialize(u);st.pop('cut',None);u.emu_start(entry,STOP,count=3000);got=observed(u,st)
  ok=got==wanted and bytes(u.mem_read(BASE,len(data)))==bytes(data) and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR) and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR)
  if got[0]=='return':ok=ok and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved
  passes[oi]+=int(ok)
  if not ok and len(failures)<25:failures.append({'case':case,'flag':flag,'type':typ,'mask':mask,'precision':precision,'allowed':allowed,'opt':[0,2,3][oi],'expected':wanted,'actual':got})
 key=wanted[0]+(':'+hex(wanted[1][1 if wanted[0]=='flag' else 0]) if wanted[0] in ['flag','error'] else '');outcomes[key]=outcomes.get(key,0)+1;families[family]=families.get(family,0)+1;cases+=1
report={'image_sha256':sha(original),'entry':'0x8be83c','end':'0x8be92c','cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'families':families,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[e[2] for e in engines],'actual_function_ABI_source':True,'whole_function_verified':False,'all_input_equivalence_proven':False,'limits':['Original entry-to-return or exact first error helper; checks complete ordinary public memory, error precedence/call arguments, ABI and FPCR/FPSR.','Real error helpers are unresolved external declarations in the candidate and never replaced by successful callbacks or fake stubs. Their throwing/unwind behavior remains unresolved.','All 256 flag/type byte values and all low-five capability-mask combinations exercised across the recorded families. Finite tests; faulting memory and concurrent observers excluded.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
