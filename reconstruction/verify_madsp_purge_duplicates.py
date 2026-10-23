"""Actual callable source ABI; real original helper execution; cuts before unresolved externals."""
import pathlib,struct,json,random,subprocess,os,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
OUT=ROOT/'madsp-purge-duplicates';OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/madsp-input/target.bin').read_bytes();assert sha(original)=='8b7cbaa383d3050241921e74d1334b22703193afed6ea5e9388599cc42a60fe8'
SOURCE=(ROOT/'reconstruction/madsp_purge_duplicates.c').read_text();(OUT/'madsp_purge_duplicates.c').write_text(SOURCE)
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

engines=[];diagnostics=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-Wall','-Wextra','-Werror','-c',str(OUT/'madsp_purge_duplicates.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','error',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diagnostics.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diagnostics,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);im,_=metadata(raw);assert not im,im;entry=next(v for n,v,undef in syms if n=='_madsp_purge_duplicates' and not undef);engines.append((u,entry,sha(raw)))
ref,_=engine(original);covered=set();im,starts=metadata(original);assert 0xb519cc in starts and starts[starts.index(0xb519cc)+1]==0xb51ab0

def hook(u,pc,n,_):
 assert 0xb519cc<=pc<0xb51ab0,hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
regs=list(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))+[UC_ARM64_REG_X29]+[UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
rng=random.Random(0xb519cc);cases=16384;passes=[0,0,0];failures=[];outcomes={};edges=[0,1,2,35,36,0x7fffffffffffffff,0x8000000000000000,0x8000000000000001,0xfffffffffffffffe,0xffffffffffffffff]
for case in range(cases):
 data=bytearray(rng.randbytes(0x10000));object=BASE+0x100+case%16;provider=BASE+0x800+case%16;records=BASE+0x1000+case%16;count=case%65;now=edges[case%len(edges)] if case%3 else rng.getrandbits(64);threshold=edges[(case//len(edges))%len(edges)] if case%3 else rng.getrandbits(64)
 struct.pack_into('<QQQQ',data,object-BASE+0x80,now,provider,records,records+36*count);struct.pack_into('<Q',data,provider-BASE+0x60,threshold)
 for j in range(count):
  t=edges[(case+j)%len(edges)] if case%4==0 else (now+[-37,-36,-1,0,1,36,37][(case+j)%7])&0xffffffffffffffff if case%4==1 else rng.getrandbits(64)
  struct.pack_into('<Q',data,records-BASE+36*j,t)
 data=bytes(data);saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x3000;fpsr=case%4;fpcr=((case//4)%4)<<22
 def initialize(u):
  u.mem_write(BASE,data);u.mem_write(STACK,bytes([0xa5])*0x4000)
  for r,v in zip(regs,saved):u.reg_write(r,v)
  for r,v in [(UC_ARM64_REG_X0,object),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,v)
 initialize(ref);ref.emu_start(0xb519cc,STOP,count=10000);assert ref.reg_read(UC_ARM64_REG_PC)==STOP;memory=bytes(ref.mem_read(BASE,len(data)));result=ref.reg_read(UC_ARM64_REG_X0);remaining=(struct.unpack_from('<Q',memory,object-BASE+0x98)[0]-records)//36;outcome='empty' if not count else 'unchanged' if remaining==count else 'all_removed' if not remaining else 'compacted';outcomes[outcome]=outcomes.get(outcome,0)+1
 for oi,(u,entry,_) in enumerate(engines):
  initialize(u);u.emu_start(entry,STOP,count=200000);ok=u.reg_read(UC_ARM64_REG_PC)==STOP and bytes(u.mem_read(BASE,len(data)))==memory and u.reg_read(UC_ARM64_REG_X0)==result and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPSR)==fpsr and u.reg_read(UC_ARM64_REG_FPCR)==fpcr;passes[oi]+=int(ok)
  if not ok and len(failures)<20:failures.append({'case':case,'count':count,'now':hex(now),'threshold':hex(threshold),'opt':[0,2,3][oi],'pc':hex(u.reg_read(UC_ARM64_REG_PC)),'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory})
report={'image_sha256':sha(original),'entry':'0xb519cc','end_exclusive':'0xb51ab0','original_function_bytes':228,'original_function_sha256':sha(original[0xb519cc:0xb51ab0]),'flagged_candidate_artifact_id':11902152004,'prior_flag':'decompiler_warning','cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[e[2] for e in engines],'native_imports':0,'complete_function_bounded_test':True,'all_input_equivalence_proven':False,'static_dependency_fact':'Native memmove at 0xb51a90 is unreachable in ordinary coherent memory: x1=dst+(end-dst)=end modulo 2^64, x20=end-x1=0, so branch at 0xb51a80 always skips it. No memmove stub used.','limits':['Mapped, ordinary, disjoint object/provider/record storage, 0..64 valid 36-byte records and aligned or unaligned data. No concurrent mutation, aliases, faults or MMIO.','Full modeled public memory including vacated tail bytes, machine return pointer, SP/callee-saved registers and FPCR/FPSR compared. Signed threshold and wraparound timestamp/absolute-minimum edges included.','Retains original flagged baseline record; new source and bounded original-execution evidence do not establish universal correctness or whole-image replacement.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
