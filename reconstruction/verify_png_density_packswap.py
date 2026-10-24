"""Complete-function original-byte tests, no patched instructions/callees."""
import argparse,hashlib,json,pathlib,random,struct,subprocess,time
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
P=pathlib.Path;sha=lambda b:hashlib.sha256(b).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--lane',choices=['density','packswap'],required=True);lane=p.parse_args().lane
out=P('png-density-'+lane);out.mkdir(exist_ok=True);began=time.time();raw=P('prior/dependency-closure-dossier/MACore.original').read_bytes();image=sha(raw);assert image=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
sg,sections,starts,symbols=macho(raw)
specs={'density':[(0xf6178,140,'pixel_aspect_ratio_fixed'),(0xf62dc,156,'pixels_per_inch'),(0xf6378,144,'x_pixels_per_inch'),(0xf6408,144,'y_pixels_per_inch')],'packswap':[(0x100f24,124,'do_packswap')]}[lane]
old=json.loads(P('reconstruction/DEPENDENCY_CLOSURE_CHECKPOINT.json').read_text())['accepted_function_keys'];excluded={(r['image_sha256'],int(r['entry'],0)) for r in old};ex=json.loads(P('inventory/all-unsolved-dependencies/ACCEPTED_INDEX_GAPS.json').read_text())['compiled_bounded_getter_candidate_keys'];excluded|={(a,int(b,0)) for a,b in ex}
def read(a,n):
 for _,va,size,off,_ in sections:
  if va<=a and a+n<=va+size:return raw[off+a-va:off+a-va+n]
 raise ValueError(hex(a))
for a,n,name in specs:assert (image,a) not in excluded and a in starts and starts[starts.index(a)+1]==a+n
table_checks=[]
for d,address in [(1,0x123088),(2,0x123188),(4,0x123288)]:
 expected=[]
 for value in range(256):
  v=value
  if d==1:v=((v&0x55)<<1)|((v>>1)&0x55)
  if d<=2:v=((v&0x33)<<2)|((v>>2)&0x33)
  v=((v<<4)|(v>>4))&255;expected.append(v)
 actual=read(address,256);assert actual==bytes(expected)
 table_checks.append({'depth':d,'address':hex(address),'bytes':256,'sha256':sha(actual),'all_256_values_match':True})
source=P('reconstruction/macore_png_density_packswap.c');(out/source.name).write_bytes(source.read_bytes())
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
rng=random.Random(0xf6178 if lane=='density' else 0x100f24);cases=16384;passes=[0,0,0];rows=[];failures=[];edges=[0,1,2,3,255,256,65535,65536,0x1000000,0x1000001,0x7ffffffe,0x7fffffff,0x80000000,0x80000001,0xfffffffe,0xffffffff]
for entry,n,name in specs:
 bounds[0]=(entry,entry+n);before=set(covered);per=[0,0,0];aliases=0;patterns=set();outcomes=set()
 for case in range(cases):
  data=bytearray(rng.randbytes(SIZE));obj=MEM+0x100+(case&15);io=obj-MEM;ctx=MEM+0x80;info=obj
  if lane=='density':
   data[io+8]=(rng.getrandbits(8)|128) if case%8!=0 else rng.getrandbits(8)&127
   data[io+0xe8]=1 if case%8!=1 else rng.choice([0,2,255])
   x=edges[(case//8)%len(edges)] if case<8192 else rng.getrandbits(32)
   y=edges[(case//128)%len(edges)] if case<8192 else rng.getrandbits(32)
   if case%4==0:y=x
   struct.pack_into('<II',data,io+0xe0,x,y)
   args=[0 if case%257==0 else ctx,0 if case%257==1 else obj]+[rng.getrandbits(64) for _ in range(6)]
  else:
   d=[1,2,4,0,3,7,8,255][case%8];data[io+0x11]=d
   length=[0,1,2,3,15,16,255,256,257,511,512,1024,0xffffffffffffffff,0x8000000000000000][(case//8)%14]
   struct.pack_into('<Q',data,io+8,length)
   q=MEM+0x1800+(case&15)
   if case%3==0:q=obj+rng.choice([0,8,0x11,0x12,0x18,0x20]);aliases+=1
   # 256-byte permutations guarantee every original table entry is tested.
   if case%3==1:data[q-MEM:q-MEM+1024]=bytes(range(256))*4
   args=[obj,q]+[rng.getrandbits(64) for _ in range(6)]
  initial=[rng.getrandbits(64) for _ in preserved];fpcr=((case//512)%4<<22)|((case//2048)%4<<24);fpsr=(case*0x01010101)&0xf800009f
  for ix,(u,sy) in enumerate([(ref,{})]+engines):
   u.mem_write(MEM,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x8000)
   for reg,v in zip(preserved,initial):u.reg_write(reg,v)
   u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,STOP)
   for k,v in enumerate(args):
    if k<8:u.reg_write(getattr(ac,f'UC_ARM64_REG_X{k}'),v)
    else:u.mem_write(STACK+0x4000+(k-8)*8,struct.pack('<Q',v))
   u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr);u.emu_start(entry if ix==0 else sy['_ml_png_'+name],STOP,count=1000000)
   ret=u.reg_read(ac.UC_ARM64_REG_X0)&0xffffffff if lane=='density' else None
   actual=(ret,bytes(u.mem_read(MEM,SIZE)),u.reg_read(ac.UC_ARM64_REG_FPCR),u.reg_read(ac.UC_ARM64_REG_FPSR));assert u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x4000 and u.reg_read(ac.UC_ARM64_REG_PC)==STOP
   assert [u.reg_read(r) for r in preserved]==initial
   if ix==0:expected=actual;outcomes.add(ret)
   elif actual==expected:passes[ix-1]+=1;per[ix-1]+=1
   else:
    failure={'entry':hex(entry),'name':name,'case':case,'optimization':[0,2,3][ix-1],'original_return':expected[0],'source_return':ret,'original_fpsr':expected[3],'source_fpsr':actual[3],'memory_first_difference':next((i for i,(a,b) in enumerate(zip(expected[1],actual[1])) if a!=b),None),'args':list(map(hex,args)),'memory_hex':bytes(data).hex(),'fpcr':hex(fpcr),'fpsr':hex(fpsr)};failures.append(failure);write(out/'FIRST_MISMATCH.json',failure);raise AssertionError(str({k:v for k,v in failure.items() if k!='memory_hex'}))
  if case%2048==0:write(out/'PROGRESS.json',{'name':name,'case':case,'passes':passes})
 loc=sorted(covered-before);assert len(loc)==n//4,(name,len(loc),n//4)
 rows.append({'image_sha256':image,'entry':hex(entry),'end_exclusive':hex(entry+n),'name':name,'original_bytes':n,'original_function_sha256':sha(read(entry,n)),'cases':cases,'comparisons':cases*3,'passes':per,'mismatches':0,'all_original_instructions_exercised':True,'original_instruction_locations':list(map(hex,loc)),'aliased_cases':aliases,'output_patterns':len(patterns),'return_outcomes':len(outcomes),'complete_function_bounded_test':True});write(out/'INTERMEDIATE.json',{'functions':rows,'failures':failures})
report={'image_sha256':image,'lane':lane,'table_checks':table_checks,'functions':rows,'complete_functions':len(rows),'original_bytes':sum(r['original_bytes'] for r in rows),'comparisons':sum(r['comparisons'] for r in rows),'passes':passes,'mismatches':0,'failures':failures,'source_sha256':sha(source.read_bytes()),'modules':modules,'native_imports':0,'native_callees':0,'native_stubs_used':False,'elapsed_seconds':time.time()-began,'limits':['Finite mapped ordinary-memory inputs and aliased public buffers only; not all-input proof.','No fault/MMIO/race or asynchronous observer equivalence.','Private stack alias inputs excluded.','Void setter result registers are not observable return values and are not compared.','Whole native image builds and Payload integration remain unresolved.']};write(out/'REPORT.json',report);print(json.dumps(report,indent=2))
