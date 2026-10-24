"""Complete-function original-byte tests, no patched instructions/callees."""
import argparse,hashlib,json,pathlib,random,struct,subprocess,time
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
P=pathlib.Path;sha=lambda b:hashlib.sha256(b).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--lane',choices=['chromaticity','configuration'],required=True);lane=p.parse_args().lane
out=P('png-color-'+lane);out.mkdir(exist_ok=True);began=time.time();raw=P('prior/dependency-closure-dossier/MACore.original').read_bytes();image=sha(raw);assert image=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
sg,sections,starts,symbols=macho(raw)
specs={'chromaticity':[(0xf6780,276,'cHRM'),(0xf6894,308,'cHRM_XYZ')],'configuration':[(0x100a0c,20,'set_bgr'),(0x100a20,32,'set_swap'),(0x100a40,40,'set_packing'),(0x100a68,32,'set_packswap'),(0x100a88,40,'set_shift'),(0x100cac,20,'set_invert_mono'),(0x100c84,20,'set_swap_alpha'),(0x100c98,20,'set_invert_alpha'),(0x100ab0,40,'set_interlace_handling')]}[lane]
old=json.loads(P('reconstruction/DEPENDENCY_CLOSURE_CHECKPOINT.json').read_text())['accepted_function_keys'];excluded={(r['image_sha256'],int(r['entry'],0)) for r in old};ex=json.loads(P('inventory/all-unsolved-dependencies/ACCEPTED_INDEX_GAPS.json').read_text())['compiled_bounded_getter_candidate_keys'];excluded|={(a,int(b,0)) for a,b in ex}
def read(a,n):
 for _,va,size,off,_ in sections:
  if va<=a and a+n<=va+size:return raw[off+a-va:off+a-va+n]
 raise ValueError(hex(a))
for a,n,name in specs:assert (image,a) not in excluded and a in starts and starts[starts.index(a)+1]==a+n
# Original binary64 constant identity independently checked against literal bytes.
assert struct.unpack('<Q',read(0x11bdc8,8))[0]==0x3ee4f8b588e368f1
source=P('reconstruction/macore_png_color_transform.c');(out/source.name).write_bytes(source.read_bytes())
MEM,STACK,STOP=0x30000000,0x40000000,0x50000000;SIZE=0x4000
build=[];engines=[];modules=[]
def load(b):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);segs,_,_,sy=macho(b)
 for name,va,vs,off,fl in segs:
  if name=='__PAGEZERO' or not vs:continue
  lo=va&~4095;hi=(va+vs+4095)&~4095;u.mem_map(lo,hi-lo)
  if fl:u.mem_write(va,b[off:off+fl])
 u.mem_map(MEM,SIZE);u.mem_map(STACK,0x8000);u.mem_map(STOP,4096);return u,sy
for opt in (0,2,3):
 obj,lib=out/f'O{opt}.o',out/f'O{opt}.dylib'
 for cmd in [['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffp-contract=off','-frounding-math','-c',str(source),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-no_fixup_chains','-dylib',str(obj),'-o',str(lib)]]:
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});write(out/'BUILD.json',build);assert r.returncode==0,r.stderr
 r=subprocess.run(['llvm-nm-18','--undefined-only',str(lib)],capture_output=True,text=True,timeout=60);assert r.returncode==0 and not r.stdout.strip(),r.stdout
 u,sy=load(lib.read_bytes());engines.append((u,sy));modules.append({'optimization':opt,'sha256':sha(lib.read_bytes())})
ref,_=load(raw);covered=set();bounds=[(0,0)]
def hook(u,pc,size,_):assert bounds[0][0]<=pc<bounds[0][1],hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
preserved=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
rng=random.Random(0xf6780 if lane=='chromaticity' else 0x100a88);cases=16384 if lane=='chromaticity' else 8192;passes=[0,0,0];rows=[];failures=[];edges=[0,1,2,3,255,256,65535,65536,0x1000000,0x1000001,0x7ffffffe,0x7fffffff,0x80000000,0x80000001,0xfffffffe,0xffffffff]
for entry,n,name in specs:
 bounds[0]=(entry,entry+n);before=set(covered);per=[0,0,0];aliases=0;patterns=set();outcomes=set()
 for case in range(cases):
  data=bytearray(rng.randbytes(SIZE));obj=MEM+0x100+(case&15);io=obj-MEM;ctx=MEM+0x80;info=obj
  struct.pack_into('<H',data,io+0x7e,(rng.getrandbits(16)|2) if (case//512)%4!=1 else rng.getrandbits(16)&~2)
  for k,off in enumerate(range(0x34,0x80,4)):struct.pack_into('<I',data,io+off,edges[(case//512+k)%len(edges)] if case<8192 else rng.getrandbits(32))
  # Restore validity after initializing neighboring numeric fields.
  struct.pack_into('<H',data,io+0x7e,(rng.getrandbits(16)|2) if (case//512)%4!=1 else rng.getrandbits(16)&~2)
  pointers=[]
  for k in range(9):
   target=MEM+0x1000+32*k+(case&15)
   if case%4==0:target=obj+rng.choice([8,0x34,0x38,0x3c,0x40,0x44,0x48,0x4c,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x6c,0x70,0x74,0x78,0x7c]);aliases+=int(bool(case&(1<<k)))
   elif case%4==1 and k>0:target=pointers[0] or target;aliases+=int(bool(case&(1<<k)))
   pointers.append(target if case&(1<<k) else 0)
  if (case//512)%16==0:ctx=0
  if (case//512)%16==2:info=0
  patterns.add(tuple(bool(p) for p in pointers));args=[ctx,info]+pointers
  if lane=='configuration':
   data[io+0x260]=case%256;data[io+0x25c]=(case//256)%256
   q=MEM+0x2000+(case&15)
   if case%4==0:q=obj+rng.choice([0x12b,0x12c,0x12d,0x2d1,0x2d2,0x2d3,0x2d4,0x2d5,0x2d6,0x2d7,0x2d8,0x2d9]);aliases+=1
   args=[0 if case%257==0 else obj,q,case]+[rng.getrandbits(64) for _ in range(8)]
  initial=[rng.getrandbits(64) for _ in preserved];fpcr=((case//512)%4<<22)|((case//2048)%4<<24);fpsr=(case*0x01010101)&0xf800009f
  for ix,(u,sy) in enumerate([(ref,{})]+engines):
   u.mem_write(MEM,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x8000)
   for reg,v in zip(preserved,initial):u.reg_write(reg,v)
   u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,STOP)
   for k,v in enumerate(args):
    if k<8:u.reg_write(getattr(ac,f'UC_ARM64_REG_X{k}'),v)
    else:u.mem_write(STACK+0x4000+(k-8)*8,struct.pack('<Q',v))
   u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr);u.emu_start(entry if ix==0 else sy['_ml_png_'+name],STOP,count=30000)
   ret=u.reg_read(ac.UC_ARM64_REG_X0) if lane=='chromaticity' or name=='set_interlace_handling' else None
   actual=(ret,bytes(u.mem_read(MEM,SIZE)),u.reg_read(ac.UC_ARM64_REG_FPCR),u.reg_read(ac.UC_ARM64_REG_FPSR));assert u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x4000 and u.reg_read(ac.UC_ARM64_REG_PC)==STOP
   assert [u.reg_read(r) for r in preserved]==initial
   if ix==0:expected=actual;outcomes.add(ret)
   elif actual==expected:passes[ix-1]+=1;per[ix-1]+=1
   else:
    failure={'entry':hex(entry),'name':name,'case':case,'optimization':[0,2,3][ix-1],'original_return':expected[0],'source_return':ret,'original_fpsr':expected[3],'source_fpsr':actual[3],'memory_first_difference':next((i for i,(a,b) in enumerate(zip(expected[1],actual[1])) if a!=b),None),'args':list(map(hex,args)),'memory_hex':bytes(data).hex(),'fpcr':hex(fpcr),'fpsr':hex(fpsr)};failures.append(failure);write(out/'FIRST_MISMATCH.json',failure);raise AssertionError(str({k:v for k,v in failure.items() if k!='memory_hex'}))
  if case%2048==0:write(out/'PROGRESS.json',{'name':name,'case':case,'passes':passes})
 loc=sorted(covered-before);assert len(loc)==n//4,(name,len(loc),n//4)
 rows.append({'image_sha256':image,'entry':hex(entry),'end_exclusive':hex(entry+n),'name':name,'original_bytes':n,'original_function_sha256':sha(read(entry,n)),'cases':cases,'comparisons':cases*3,'passes':per,'mismatches':0,'all_original_instructions_exercised':True,'original_instruction_locations':list(map(hex,loc)),'aliased_cases':aliases,'output_patterns':len(patterns),'return_outcomes':len(outcomes),'complete_function_bounded_test':True});write(out/'INTERMEDIATE.json',{'functions':rows,'failures':failures})
report={'image_sha256':image,'lane':lane,'functions':rows,'complete_functions':len(rows),'original_bytes':sum(r['original_bytes'] for r in rows),'comparisons':sum(r['comparisons'] for r in rows),'passes':passes,'mismatches':0,'failures':failures,'source_sha256':sha(source.read_bytes()),'modules':modules,'native_imports':0,'native_callees':0,'native_stubs_used':False,'elapsed_seconds':time.time()-began,'limits':['Finite mapped ordinary-memory inputs and aliased public buffers only; not all-input proof.','No fault/MMIO/race or asynchronous observer equivalence.','Private stack alias inputs excluded.','Void setter result registers are not observable return values and are not compared.','Whole native image builds and Payload integration remain unresolved.']};write(out/'REPORT.json',report);print(json.dumps(report,indent=2))
