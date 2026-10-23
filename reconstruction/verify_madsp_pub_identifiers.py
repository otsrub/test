"""Actual callable source ABI; real original helper execution; cuts before unresolved externals."""
import pathlib,struct,json,random,subprocess,os,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
LANE=os.environ.get('REA_LANE','identifiers');start,end,symbol={'identifiers':(0x896250,0x896368,'_madsp_pub_offset_identifiers'),'attack':(0x8963ac,0x896428,'_madsp_pub_attack_identifiers'),'point':(0x89642c,0x896478,'_madsp_pub_attack_point')}[LANE]
OUT=ROOT/('madsp-pub-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/madsp-input/target.bin').read_bytes();assert sha(original)=='8b7cbaa383d3050241921e74d1334b22703193afed6ea5e9388599cc42a60fe8'
SOURCE=(ROOT/'reconstruction/madsp_pub_offset_identifiers.c').read_text();(OUT/'madsp_pub_offset_identifiers.c').write_text(SOURCE)
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
engines=[];diags=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-fno-stack-protector","-Wall","-Wextra","-Werror","-c",str(OUT/'madsp_pub_offset_identifiers.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','error',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);entry=next(v for n,v,undefined in syms if n==symbol and not undefined);im,_=metadata(raw);assert not im,im;engines.append((u,entry,sha(raw)))


ref,_=engine(original);covered=set()
def ref_hook(u,pc,n,_):assert start<=pc<end,hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,ref_hook)
rng=random.Random(start);passes=[0,0,0];failures=[];cases=2048
regs=list(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))+[UC_ARM64_REG_X29]+[UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
for case in range(cases):
 data=bytearray(rng.randbytes(0x10000));object=BASE+0x100+case%16;frame=BASE+0x8000;record=BASE+0xf000;heap=BASE+0x6800+case%16;sp=STACK+0x3000;saved=[rng.getrandbits(64) for _ in regs];fpsr=case%4;fpcr=((case//4)%4)<<22
 ref.mem_write(BASE,bytes(data));ref.mem_write(STACK,bytes([0xa5])*0x4000)
 for r,v in zip(regs,saved):ref.reg_write(r,v)
 for r,v in [(UC_ARM64_REG_X26,object),(UC_ARM64_REG_X19,frame+0x390),(UC_ARM64_REG_SP,frame),(UC_ARM64_REG_X0,heap),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:ref.reg_write(r,v)
 ref.emu_start(start,end,count=500);assert ref.reg_read(UC_ARM64_REG_PC)==end and ref.reg_read(UC_ARM64_REG_SP)==frame
 wanted=([0x52418]+[ref.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X19,UC_ARM64_REG_X23,UC_ARM64_REG_X8]] if LANE=='identifiers' else [0xc13b48,ref.reg_read(UC_ARM64_REG_X0),ref.reg_read(UC_ARM64_REG_X20),0,0,0,0,0] if LANE=='attack' else [0x52418]+[ref.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X28,UC_ARM64_REG_X8]]+[0]);memory=bytes(ref.mem_read(BASE,len(data)))
 assert memory[record-BASE:record-BASE+64]==data[record-BASE:record-BASE+64]
 for oi,(u,entry,_) in enumerate(engines):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x4000)
  for r,v in zip(regs,saved):u.reg_write(r,v)
  for r,v in [(UC_ARM64_REG_X0,object),(UC_ARM64_REG_X1,frame),(UC_ARM64_REG_X2,record if LANE=='identifiers' else heap),(UC_ARM64_REG_X3,record),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,v)
  u.emu_start(entry,STOP,count=20000);got=list(struct.unpack('<8Q',bytes(u.mem_read(record,64))));mem=bytearray(u.mem_read(BASE,len(data)));mem[record-BASE:record-BASE+64]=data[record-BASE:record-BASE+64]
  ok=got==wanted and bytes(mem)==memory and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPSR)==fpsr and u.reg_read(UC_ARM64_REG_FPCR)==fpcr
  passes[oi]+=int(ok)
  if not ok and len(failures)<20:failures.append({'case':case,'alignment':case%16,'opt':[0,2,3][oi],'expected_transfer':wanted,'actual_transfer':got,'memory_equal':bytes(mem)==memory})
report={'image_sha256':sha(original),'constructor_entry':'0x8961a8','lane':LANE,'phase_entry':hex(start),'phase_end_exclusive':hex(end),'original_phase_bytes':end-start,'original_phase_sha256':sha(original[start:end]),'cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[e[2] for e in engines],'next_original_callee':hex(wanted[0]),'whole_constructor_verified':False,'all_input_equivalence_proven':False,'limits':['Synthetic post-helper allocated object and constructor-frame states. Execute all original phase bytes until BEFORE the real native assignment helper; no helper body or stub is called.','Exact inline and heap string writes preserve untouched padding holes. Allocator-return lanes start with a real allocated-memory entry-state assumption, not an allocator stub. Object/frame/heap bytes compared.','Compare full modeled object/frame data and known integer transfer/live-register values; the source record buffer is a separate analysis output, excluded only from original-state memory comparison. Source function ABI/callee-saved state and FPCR/FPSR checked.','Does not execute original constructor prologue, preceding base/member constructors, assignment helper, allocator, cleanup, exceptions or full object lifecycle. Unknown types, further live-register contracts and caller integration remain open.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
