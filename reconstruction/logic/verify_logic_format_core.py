"""Actual callable source ABI; real original helper execution; cuts before unresolved externals."""
import pathlib,struct,json,random,subprocess,os,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
LANE=os.environ['REA_LANE'];assert LANE in ['fill','core'];OUT=ROOT/('format-core-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=(ROOT/'reconstruction/logic/logic_format_core_candidate.c').read_text();(OUT/'logic_format_core_candidate.c').write_text(SOURCE)
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
orig_imports,starts=metadata(original);assert orig_imports[0xf0bff4]=='_memmove'
for a,end in [(0x8be304,0x8be44c),(0x8b586c,0x8b5ab0)]:assert starts[starts.index(a)+1]==end
engines=[];diags=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-fno-stack-protector","-Wall","-Wextra","-Werror","-c",str(OUT/'logic_format_core_candidate.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','dynamic_lookup',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);entry=next(v for n,v,undefined in syms if n==('_logic_fill' if LANE=='fill' else '_logic_format_specs') and not undefined);im,_=metadata(raw)
 assert set(im.values())<={'_memmove','_logic_format_error_original_8b4614'},im
 st={}
 def compiled_hook(u,pc,n,st):
  if pc in st['imports']:
   name=st['imports'][pc];st['cut']='memmove' if name=='_memmove' else 'error';u.emu_stop()
 st['imports']=im;u.hook_add(UC_HOOK_CODE,compiled_hook,st);engines.append((u,entry,sha(raw),st))
ref,_=engine(original);state={};covered=set();calls={};ranges=[(0x8b586c,0x8b5ab0),(0x8be304,0x8be83c),(0x8ba1c0,0x8ba3b4),(0x8b47a0,0x8b493c)]
def ref_hook(u,pc,n,_):
 if pc in [0x8b4614,0xf0bff4]:state['cut']='error' if pc==0x8b4614 else 'memmove';u.emu_stop();return
 assert any(a<=pc<b for a,b in ranges),hex(pc);covered.add(pc)
 if pc in [0x8be304,0x8ba1c0,0x8be44c,0x8be5bc,0x8be770,0x8b47a0]:calls[hex(pc)]=calls.get(hex(pc),0)+1
ref.hook_add(UC_HOOK_CODE,ref_hook)
regs=list(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))+[UC_ARM64_REG_X29]+[UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
rng=random.Random(0x8b586c+(LANE=='fill'));passes=[0,0,0];cases=0;failures=[];outcomes={};families={}
def inputs():
 if LANE=='fill':
  for c in range(256):
   for second in [ord('<'),ord('>'),ord('^'),ord('x'),ord('}')]:
    for length in [1,2,4]:yield ('all-leading-bytes',bytes([c,second,0x80,0x80]),length,0)
  for text in [b'\xc2\x80<',b'\xe2\x82\xac^',b'\xf0\x9f\x98\x80>',b'\xc0\x80<',b'\xed\xa0\x80<',b'\xf4\x90\x80\x80>',b'{<',b'}^']:
   for n in range(1,len(text)+1):
    for _ in range(16):yield ('unicode-and-brace-boundaries',text,n,0)
  for _ in range(8192):
   text=rng.randbytes(8);yield ('random-bytes',text,rng.randrange(1,9),0)
 else:
  texts=[b'',b'}',b':',b'<',b'x',b'+',b'-',b' ',b'#',b'0',b'10',b'2147483647',b'2147483648',b'.',b'.0',b'.123',b'{}',b'{0}',b'{1}',b'{01}',b'{:}',b'{x}',b'.{}',b'.{2}',b'<+#010.3LnX}',b'*^+#08.2f}',b'\xc2\x80<8d}',b'{<',b'\xff}',b'Lnd}',b'nX}',b'8.2f}',b'8.2?}',b'8Lx}',b'10xQ',b'00000000000']
  for mask in range(512):
   for text in texts:yield ('all-mask-combinations',text,len(text),mask)
  for c in range(256):yield ('all-leading-bytes',bytes([c,ord('}'),0x80,0x80]),4,0x1ff)
  for _ in range(16384):
   text=bytes(rng.choice(b'0123456789{}.:x+ #0<>^Lndf?') for _ in range(rng.randrange(0,25)));yield ('random-grammar-and-truncation',text,rng.randrange(len(text)+1),rng.randrange(65536))
def observed(u,st):
 kind=st.get('cut','return')
 if kind=='return':return (kind,[u.reg_read(UC_ARM64_REG_X0)])
 return (kind,[u.reg_read(r) for r in ([UC_ARM64_REG_X0] if kind=='error' else [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2])])
start=0x8be304 if LANE=='fill' else 0x8b586c
for case,(family,text,length,mask) in enumerate(inputs()):
 data=bytearray(rng.randbytes(0x1000));spec=BASE+0x100+case%16;ctx=BASE+0x200+(case//16)%16;p=BASE+0x500+case%16;end=p+length
 data[p-BASE:p-BASE+len(text)]=text;struct.pack_into('<QQIQ',data,ctx-BASE,p,end,case%5,rng.getrandbits(64));struct.pack_into('<Q',data,ctx-BASE+24,rng.choice([0,1,0xffffffff,0xffffffffffffffff,rng.getrandbits(64)]))
 saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x3000;fpsr=case%4;fpcr=((case//4)%4)<<22;args=[spec,ctx,end if LANE=='fill' else mask]
 def initialize(u):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x4000)
  for r,v in zip(regs,saved):u.reg_write(r,v)
  for r,v in [(UC_ARM64_REG_X0,args[0]),(UC_ARM64_REG_X1,args[1]),(UC_ARM64_REG_X2,args[2]),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,v)
 initialize(ref);state.clear();ref.emu_start(start,STOP,count=5000);wanted=observed(ref,state);memory=bytes(ref.mem_read(BASE,len(data)))
 if wanted[0]=='return':assert ref.reg_read(UC_ARM64_REG_PC)==STOP and ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
 for oi,(u,entry,_,st) in enumerate(engines):
  initialize(u);st.pop('cut',None);u.emu_start(entry,STOP,count=20000);got=observed(u,st)
  ok=got==wanted and bytes(u.mem_read(BASE,len(data)))==memory and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR) and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR)
  if got[0]=='return':ok=ok and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved
  passes[oi]+=int(ok)
  if not ok and len(failures)<25:failures.append({'case':case,'family':family,'input':text.hex(),'length':length,'mask':mask,'opt':[0,2,3][oi],'expected':wanted,'actual':got,'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory})
 key=wanted[0]+(':'+hex(wanted[1][0]) if wanted[0]=='error' else '');outcomes[key]=outcomes.get(key,0)+1;families[family]=families.get(family,0)+1;cases+=1
report={'image_sha256':sha(original),'entry':hex(start),'lane':LANE,'cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'families':families,'actual_original_helper_calls':calls,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[e[2] for e in engines],'source_uses_actual_entry_return_abi':True,'whole_function_verified':False,'all_input_equivalence_proven':False,'unresolved_original_dependencies':{'0xf0bff4':'_memmove','0x8b4614':'original throwing helper'},'limits':['Uninterrupted original parser/helper execution through return or entry to real memmove/throw helper, never substituting a fake callee.','Compiled candidates expose actual function ABI and real unresolved extern declarations. Dynamic lookup test dylibs are not complete production builds.','Compare complete modeled public input/spec/context memory, returned value or external-call args, FPCR/FPSR, and full callee-saved register set/SP on returns.','Ordinary disjoint mapped memory; input bounded to 24 bytes, physically mapped after logical end, state pointers nonwrapping. Aliases, faults, MMIO, concurrent observers, real memmove behavior and exceptions/unwinding remain unresolved.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
