"""Actual callable source ABI; real original helper execution; cuts before unresolved externals."""
import pathlib,struct,json,random,subprocess,os,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
LANE=os.environ.get('REA_LANE','entry');assert LANE in ['entry','postalloc'];OUT=ROOT/('madsp-string-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/madsp-input/target.bin').read_bytes();assert sha(original)=='8b7cbaa383d3050241921e74d1334b22703193afed6ea5e9388599cc42a60fe8'
SOURCE=(ROOT/'reconstruction/madsp_string_copy_candidate.c').read_text();(OUT/'madsp_string_copy_candidate.c').write_text(SOURCE)
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
 for argv in (['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-Wall','-Wextra','-Werror','-c',str(OUT/'madsp_string_copy_candidate.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','dynamic_lookup',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diagnostics.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diagnostics,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);im,_=metadata(raw);assert set(im.values())=={'__Znwm','_memmove','_madsp_length_error_original_36e30'},im
 symbol='_madsp_string_copy' if LANE=='entry' else '_madsp_string_copy_after_allocation';entry=next(v for n,v,undef in syms if n==symbol and not undef);st={}
 def hook(u,pc,n,st):
  if pc in st['imports']:st['cut']=st['imports'][pc];u.emu_stop()
 st['imports']=im;u.hook_add(UC_HOOK_CODE,hook,st);engines.append((u,entry,sha(raw),st))
ref,_=engine(original);state={};covered=set();im,starts=metadata(original);assert im[0xc13b48]=='__Znwm' and im[0xc1407c]=='_memmove';assert 0x41038 in starts and 0x410b0 in starts
cuts={0xc13b48:'__Znwm',0xc1407c:'_memmove',0x36e30:'_madsp_length_error_original_36e30'}
def reference_hook(u,pc,n,_):
 if pc in cuts:state['cut']=cuts[pc];u.emu_stop();return
 assert 0x41038<=pc<0x410b0,hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,reference_hook)
def observed(u,st):
 cut=st.get('cut');assert cut
 args=[u.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2]]
 return (cut,args[:1] if cut=='__Znwm' else args if cut=='_memmove' else [])
rng=random.Random(0x41038+len(LANE));cases=8192;passes=[0,0,0];failures=[];outcomes={}
lengths=list(range(40))+[63,64,127,128,255,256,511,512,0x7ffffffffffffff0,0x7ffffffffffffff7,0x7ffffffffffffff8,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff]
for case in range(cases):
 data=rng.randbytes(0x10000);dst=BASE+0x100+case%16;src=BASE+0x1000+case%16;heap=BASE+0x3000+case%16;length=lengths[case%len(lengths)] if LANE=='entry' else 23+case%490;capacity=25 if length|7==23 else ((length|7)+1)&0xffffffffffffffff;sp=STACK+0x3000
 ref.mem_write(BASE,data);ref.mem_write(STACK,bytes([0xa5])*0x4000);state.clear()
 for r,v in [(UC_ARM64_REG_X0,dst),(UC_ARM64_REG_X1,src),(UC_ARM64_REG_X2,length),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp)]:ref.reg_write(r,v)
 if LANE=='postalloc':
  for r,v in [(UC_ARM64_REG_X0,heap),(UC_ARM64_REG_X19,length),(UC_ARM64_REG_X20,capacity),(UC_ARM64_REG_X21,src),(UC_ARM64_REG_X22,dst),(UC_ARM64_REG_SP,sp-0x30)]:ref.reg_write(r,v)
 start=0x41038 if LANE=='entry' else 0x41088;ref.emu_start(start,STOP,count=500);want=observed(ref,state);memory=bytes(ref.mem_read(BASE,len(data)));outcomes[want[0]]=outcomes.get(want[0],0)+1
 for oi,(u,entry,_,st) in enumerate(engines):
  u.mem_write(BASE,data);u.mem_write(STACK,bytes([0xa5])*0x4000);st.pop('cut',None)
  for r,v in [(UC_ARM64_REG_X0,dst),(UC_ARM64_REG_X1,src),(UC_ARM64_REG_X2,length),(UC_ARM64_REG_X3,capacity),(UC_ARM64_REG_X4,heap),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp)]:u.reg_write(r,v)
  u.emu_start(entry,STOP,count=10000);got=observed(u,st);ok=got==want and bytes(u.mem_read(BASE,len(data)))==memory;passes[oi]+=int(ok)
  if not ok and len(failures)<20:failures.append({'case':case,'length':length,'opt':[0,2,3][oi],'expected':want,'actual':got,'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory})
report={'image_sha256':sha(original),'function_entry':'0x41038','compiler_adjacent_end':'0x410b0','compiler_envelope_bytes':120,'compiler_envelope_sha256':sha(original[0x41038:0x410b0]),'lane':LANE,'cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[e[2] for e in engines],'whole_function_runtime_verified':False,'all_input_equivalence_proven':False,'limits':['Stop BEFORE actual operator new, memmove or native length-error function. No fabricated dependency implementation or successful callback.','Entry lane compares capacity/length boundary dispatch and writes; allocation continuation lane assumes allocated storage and compares exact metadata, transfer arguments and modeled memory.','No native allocation, copy library, error unwinding, stack/callee-saved ABI equivalence after unresolved calls or full lifecycle execution. Source compiled with real unresolved dependencies; it is a candidate, not a complete binary replacement.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
