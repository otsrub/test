import json, os, pathlib, random, struct, subprocess
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

ROOT=pathlib.Path.cwd()
parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')])
ROOT=pathlib.Path.cwd()
LANE=os.environ.get('REA_LANE','up')
start,stop,flag,symbol={
 'sub':(0x3c18c,0x3c4d4,0x10,'_mobilelogic_png_sub_transform'),
 'up':(0x3c4d4,0x3c5c4,0x20,'_mobilelogic_png_up_transform'),
 'average':(0x3c5c4,0x3c87c,0x40,'_mobilelogic_png_average_transform'),
 'paeth':(0x3c87c,0x3cde8,0x80,'_mobilelogic_png_paeth_transform'),
}[LANE]
OUT=ROOT/('macore-png-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/macore-input/target.bin').read_bytes()
assert sha(original)=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
source_file='macore_png_paeth_transform.c' if LANE=='paeth' else 'macore_png_filter_transforms.c'
source=(ROOT/'reconstruction'/source_file).read_bytes()
(OUT/source_file).write_bytes(source)
engines=[];diagnostics=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (
  ['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-Wall','-Wextra','-Werror','-c',str(OUT/source_file),'-o',str(obj)],
  ['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','error',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diagnostics.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diagnostics,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);assert not [n for n,v,undef in syms if undef]
 entry=next(v for n,v,undef in syms if n==symbol and not undef);engines.append((u,entry,sha(raw)))
ref,_=engine(original);covered=set()
def hook(u,pc,n,_):
 assert 0x3c18c<=pc<0x3d488,hex(pc)
 covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
regs=list(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))+[UC_ARM64_REG_X29]+[UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
rng=random.Random(start);cases=4096;passes=[0,0,0];failures=[];families={}
for case in range(cases):
 data=bytearray(rng.randbytes(SIZE));context=BASE+0x100+case%16;row=BASE+0x1000+case%16;previous=BASE+0x2000+(case//16)%16;output=BASE+0x3000+(case//256)%16
 depth=(case%255)+1;bpp=(depth+7)//8
 if case%64==0:depth=bpp=0;length=0
 else:length=bpp+[0,1,7,8,15,16,17,23,24,31,32,33,63,64,65,127,128,255,256,511][(case//16)%20] if case%3 else bpp+rng.randrange(513)
 for offset,pointer in [(0x218,previous),(0x220,row),(0x228,output)]:struct.pack_into('<Q',data,context-BASE+offset,pointer)
 family=['random','zero','full','alternating'][case%4];families[family]=families.get(family,0)+1
 if family!='random':
  a=bytes(length) if family=='zero' else bytes([255])*length if family=='full' else bytes((i*127+case)&255 for i in range(length))
  b=bytes([255])*length if family=='zero' else bytes(length) if family=='full' else bytes((i*131+17)&255 for i in range(length))
  data[row-BASE+1:row-BASE+1+length]=a;data[previous-BASE+1:previous-BASE+1+length]=b
 data=bytes(data);saved=[rng.getrandbits(64) for _ in regs];fpsr=case%4;fpcr=(((case//4)%4)<<22)|(((case//16)%4)<<24);sp=STACK+0x3000
 def initialize(u):
  u.mem_write(BASE,data);u.mem_write(STACK,bytes([0xa5])*0x4000)
  for r,v in zip(regs,saved):u.reg_write(r,v)
  u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
  for r,v in ((UC_ARM64_REG_SP,sp),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_FPCR,fpcr),(UC_ARM64_REG_FPSR,fpsr)):u.reg_write(r,v)
 initialize(ref)
 for r,v in ((UC_ARM64_REG_X19,context),(UC_ARM64_REG_X8,row),(UC_ARM64_REG_X9,length),(UC_ARM64_REG_X10,0xfffffffffffffeff),(UC_ARM64_REG_X11,depth),(UC_ARM64_REG_X12,bpp),(UC_ARM64_REG_X13,flag)):ref.reg_write(r,v)
 ref.emu_start(start,stop,count=50000);assert ref.reg_read(UC_ARM64_REG_PC)==stop
 wanted=bytes(ref.mem_read(BASE,SIZE));wanted_pointer=ref.reg_read(UC_ARM64_REG_X8)
 # A separate byte-level oracle checks the source's stated PNG contract.
 oracle=bytearray(data);oracle[output-BASE]={'sub':1,'up':2,'average':3,'paeth':4}[LANE]
 for i in range(length):
  left=data[row-BASE+1+i-bpp] if i>=bpp else 0;above=data[previous-BASE+1+i]
  predictor=left if LANE=='sub' else above if LANE=='up' else (left+above)//2
  if LANE=='paeth':
   corner=data[previous-BASE+1+i-bpp] if i>=bpp else 0
   estimate=left+above-corner
   distances=[abs(estimate-value) for value in [left,above,corner]]
   predictor=[left,above,corner][distances.index(min(distances))]
  oracle[output-BASE+1+i]=(data[row-BASE+1+i]-predictor)&255
 assert wanted==bytes(oracle),(case,LANE,depth,length)
 for oi,(u,entry,_) in enumerate(engines):
  initialize(u)
  for r,v in ((UC_ARM64_REG_X0,context),(UC_ARM64_REG_X1,length),(UC_ARM64_REG_X2,bpp)):u.reg_write(r,v)
  u.emu_start(entry,STOP,count=50000)
  ok=u.reg_read(UC_ARM64_REG_PC)==STOP and bytes(u.mem_read(BASE,SIZE))==wanted and u.reg_read(UC_ARM64_REG_X0)==wanted_pointer and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR) and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR)
  passes[oi]+=int(ok)
  if not ok and len(failures)<16:failures.append({'case':case,'depth':depth,'rowbytes':length,'bpp':bpp,'optimization':[0,2,3][oi],'pc':hex(u.reg_read(UC_ARM64_REG_PC)),'memory_equal':bytes(u.mem_read(BASE,SIZE))==wanted,'pointer_equal':u.reg_read(UC_ARM64_REG_X0)==wanted_pointer})
report={'image_sha256':sha(original),'original_function_entry':'0x3c144','lane':LANE,'phase_entry':hex(start),'phase_exit':hex(stop),'cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'families':families,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(source),'module_sha256':[x[2] for x in engines],'native_imports':0,'whole_function_verified':False,'all_input_equivalence_proven':False,'limits':['Post-prologue synthetic phase state with exact single fixed-filter mask; no allocator, filter scoring/selection, output/compression or exception behavior covered.', 'Ordinary disjoint context/current-row/previous-row/output storage with 16 tested alignment offsets; valid depth 1..255 and rowbytes>=ceil(depth/8), plus empty zero-depth rows. Finite lengths up to 544 bytes; aliases, faults, MMIO, concurrency excluded.', 'Scalar and original SIMD/tail paths execute uninterrupted until the exact phase exit; no native callees or fake stubs. Full modeled public memory, output pointer and FPCR/FPSR compared. Source phase ABI also checks SP and callee-saved registers.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));assert report['mismatches']==0
