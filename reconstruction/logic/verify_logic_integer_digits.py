"""Actual callable source ABI; real original helper execution; cuts before unresolved externals."""
import pathlib,struct,json,random,subprocess,os,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
LANE=os.environ['REA_LANE'];targets={'binary':(0x8c0eec,0x8c0f8c,'_logic_binary32'),'octal':(0x8c0f8c,0x8c1038,'_logic_octal32'),'hex':(0x8c1038,0x8c10dc,'_logic_hex32'),'count':(0x8c10dc,0x8c1144,'_logic_digit_count32'),'decimal':(0x8b8cd0,0x8b90b0,'_logic_decimal_write32'),'generic':(0x8c0d8c,0x8c0eec,'_logic_to_chars32')};assert LANE in targets;start,end,symbol=targets[LANE];OUT=ROOT/('integer-digits-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=(ROOT/'reconstruction/logic/logic_integer_digits.c').read_text();(OUT/'logic_integer_digits.c').write_text(SOURCE)
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
_,starts=metadata(original)
for a,b,_ in targets.values():assert starts[starts.index(a)+1]==b
assert original[0x1092bdb:0x1092c00]==b'0123456789abcdefghijklmnopqrstuvwxyz\0'
engines=[];diags=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-fno-stack-protector","-Wall","-Wextra","-Werror","-c",str(OUT/'logic_integer_digits.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','error',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);entry=next(v for n,v,undefined in syms if n==symbol and not undefined);im,_=metadata(raw);assert not im,im;engines.append((u,entry,sha(raw)))

ref,_=engine(original);covered=set();calls={};ranges=[(a,b) for a,b,_ in targets.values()]
def ref_hook(u,pc,n,_):
 assert any(a<=pc<b for a,b in ranges),hex(pc);covered.add(pc)
 if pc in [a for a,b in ranges]:calls[hex(pc)]=calls.get(hex(pc),0)+1
ref.hook_add(UC_HOOK_CODE,ref_hook)
regs=list(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))+[UC_ARM64_REG_X29]+[UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
rng=random.Random(start);passes=[0,0,0];failures=[];cases=32768;outcomes={}
edges=sorted({0,1,0xffffffff,*[min(0xffffffff,max(0,(1<<n)+delta)) for n in range(33) for delta in [-1,0,1]],*[min(0xffffffff,max(0,10**n+delta)) for n in range(11) for delta in [-1,0,1]]})
for case in range(cases):
 data=bytearray(rng.randbytes(0x1000));dst=BASE+0x300+case%16;base={'binary':2,'octal':8,'hex':16,'decimal':10}.get(LANE,2+case%35)
 if LANE=='decimal' and case<=10000:value=case
 elif LANE in ['count','generic'] and case<8960:value=case//35
 elif case<16384:value=edges[(case//8)%len(edges)]
 else:value=rng.getrandbits(32)
 n=1;v=value
 while v>=base:v//=base;n+=1
 capacity=[-1,0,1,n-1,n,n+1,32,40][case%8];limit=dst+capacity
 if LANE=='count':args=[value|(rng.getrandbits(32)<<32),base|(rng.getrandbits(32)<<32)]
 elif LANE=='decimal':args=[dst,value|(rng.getrandbits(32)<<32)]
 else:args=[dst,limit,value|(rng.getrandbits(32)<<32),base|(rng.getrandbits(32)<<32)]
 saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x3000;fpsr=case%4;fpcr=((case//4)%4)<<22
 def initialize(u):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x4000)
  for r,v in zip(regs,saved):u.reg_write(r,v)
  for r,v in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3],args):u.reg_write(r,v)
  for r,v in [(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,v)
 initialize(ref);ref.emu_start(start,STOP,count=5000);assert ref.reg_read(UC_ARM64_REG_PC)==STOP and ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
 outregs=[UC_ARM64_REG_X0] if LANE in ['count','decimal'] else [UC_ARM64_REG_X0,UC_ARM64_REG_X1];wanted=[ref.reg_read(r) for r in outregs];memory=bytes(ref.mem_read(BASE,len(data)))
 for oi,(u,entry,_) in enumerate(engines):
  initialize(u);u.emu_start(entry,STOP,count=30000);got=[u.reg_read(r) for r in outregs]
  ok=got==wanted and bytes(u.mem_read(BASE,len(data)))==memory and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR) and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR)
  passes[oi]+=int(ok)
  if not ok and len(failures)<25:failures.append({'case':case,'value':value,'base':base,'capacity':capacity,'opt':[0,2,3][oi],'expected':wanted,'actual':got,'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory})
 key='return' if LANE in ['count','decimal'] else 'capacity-error' if wanted[1] else 'success';outcomes[key]=outcomes.get(key,0)+1
report={'image_sha256':sha(original),'entry':hex(start),'end':hex(end),'original_bytes':end-start,'original_slice_sha256':sha(original[start:end]),'lane':LANE,'cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'actual_original_function_entry_counts':calls,'original_instruction_count':len(covered),'target_instruction_count':sum(start<=a<end for a in covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[e[2] for e in engines],'complete_function_bounded_tests_passed':sum(passes)==cases*3,'all_input_equivalence_proven':False,'source_module_all_imports_resolved':True,'limits':['Actual complete original entry-to-return and compiled entry-to-return; no external callees or fake stubs. Generic converter executes the real original recovered digit helpers.','uint32 values; all 35 valid bases 2..36 sampled for count/generic. Base 0/1 and bases outside the normal original caller domain excluded; no all-input claim.','Ordinary mapped destination memory with alignment varied; logical capacity -1,0 and digit-boundary sizes; compare entire public memory, return aggregate ABI, full callee-saved state/SP and FPCR/FPSR. Faults, MMIO, concurrent observers and wraparound pointers excluded.','Decimal writer has no capacity argument: tests allocate at least 10 physical output bytes and compare all writes. Original full image, code slice and digit-table hashes retained.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
