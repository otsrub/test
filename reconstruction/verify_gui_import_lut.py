"""Complete-function original-byte tests, no patched instructions/callees."""
import argparse,hashlib,json,pathlib,random,struct,subprocess,time
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
P=pathlib.Path;sha=lambda b:hashlib.sha256(b).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--lane',choices=['lut'],required=True);lane=p.parse_args().lane
out=P('gui-import-lut-source');out.mkdir(exist_ok=True);began=time.time();raw=P('prior/maplugingui-input/target.bin').read_bytes();image=sha(raw);assert image=='74caec7240779c9be25d4dbf9fde574a2783c8192cca262866b1511bb01fe1b4'
sg,sections,starts,symbols=macho(raw)
specs=[(0x865e4,76,'gui_set_import_lut')]
old=json.loads(P('reconstruction/DEPENDENCY_CLOSURE_CHECKPOINT.json').read_text())['accepted_function_keys'];excluded={(r['image_sha256'],int(r['entry'],0)) for r in old};ex=json.loads(P('inventory/all-unsolved-dependencies/ACCEPTED_INDEX_GAPS.json').read_text())['compiled_bounded_getter_candidate_keys'];excluded|={(a,int(b,0)) for a,b in ex}
def read(a,n):
 for _,va,size,off,_ in sections:
  if va<=a and a+n<=va+size:return raw[off+a-va:off+a-va+n]
 raise ValueError(hex(a))
for a,n,name in specs:assert (image,a) not in excluded and a in starts and starts[starts.index(a)+1]==a+n
table_checks=[];assert symbols['__ZN6GImage12ms_ImportLUTE']==0x474190 and symbols['__ZN6GNoise11ms_ValueTabE']==0x474290
common=next(x for x in sections if x[1]<=0x474190< x[1]+x[2]);assert common[0]=='__common' and common[4]&255==1
source=P('reconstruction/maplugingui_import_lut_source.cpp');(out/source.name).write_bytes(source.read_bytes())
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
 for cmd in [['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-std=c++17','-fno-exceptions','-fno-rtti','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffp-contract=off','-frounding-math','-c',str(source),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-no_fixup_chains','-dylib',str(obj),'-o',str(lib)]]:
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});write(out/'BUILD.json',build);assert r.returncode==0,r.stderr
 r=subprocess.run(['llvm-nm-18','--undefined-only',str(lib)],capture_output=True,text=True,timeout=60);assert r.returncode==0 and not r.stdout.strip(),r.stdout
 u,sy=load(lib.read_bytes());g=sy['__ZN6GImage12ms_ImportLUTE'];assert any(name=='__DATA' and va<=g and g+1024<=va+vs for name,va,vs,off,fl in macho(lib.read_bytes())[0]);assert bytes(u.mem_read(g,256))==bytes(256);assert bytes(u.mem_read(g-256,256))==bytes(256);assert not any((flags&0x80000400) and a<g and g-256<a+n for _,a,n,_,flags in macho(lib.read_bytes())[1]);engines.append((u,sy));modules.append({'optimization':opt,'sha256':sha(lib.read_bytes())})
ref,refsy=load(raw);assert bytes(ref.mem_read(0x474190,256))==bytes(256);covered=set();bounds=[(0,0)]
def hook(u,pc,size,_):assert bounds[0][0]<=pc<bounds[0][1],hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
preserved=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
rng=random.Random(0xf6178 if lane=='density' else 0x100f24);cases=16384;passes=[0,0,0];rows=[];failures=[];edges=[0,1,2,3,255,256,65535,65536,0x1000000,0x1000001,0x7ffffffe,0x7fffffff,0x80000000,0x80000001,0xfffffffe,0xffffffff]
for entry,n,name in specs:
 bounds[0]=(entry,entry+n);before=set(covered);per=[0,0,0];aliases=0;tested_displacements=set();patterns=set();outcomes=set()
 for case in range(cases):
  data=bytearray(rng.randbytes(SIZE));obj=MEM+0x100+(case&15);io=obj-MEM;ctx=MEM+0x80;info=obj
  global_data=bytearray(rng.randbytes(1024))
  if case%5==0:global_data[:]=bytes(range(256))*4
  displacement=[-128,-127,-64,-63,-32,-31,-16,-15,-8,-7,-4,-3,-2,-1,0,1,2,3,4,7,8,15,16,31,32,63,64,127,128,255][case%30]
  use_alias=(case//30)%3!=0;aliases+=int(use_alias)
  if use_alias:tested_displacements.add(displacement)
  args=[MEM+0x1000+(case&15)]+[rng.getrandbits(64) for _ in range(7)]
  initial=[rng.getrandbits(64) for _ in preserved];fpcr=((case//512)%4<<22)|((case//2048)%4<<24);fpsr=(case*0x01010101)&0xf800009f
  for ix,(u,sy) in enumerate([(ref,{})]+engines):
   u.mem_write(MEM,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x8000)
   g=0x474190 if ix==0 else sy['__ZN6GImage12ms_ImportLUTE']
   if ix==0:u.mem_write(g-256,bytes(256)) # real original __common data, never instructions
   u.mem_write(g,bytes(global_data))
   callargs=list(args);callargs[0]=g+displacement if use_alias else args[0]
   for reg,v in zip(preserved,initial):u.reg_write(reg,v)
   u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,STOP)
   for k,v in enumerate(callargs):
    if k<8:u.reg_write(getattr(ac,f'UC_ARM64_REG_X{k}'),v)
    else:u.mem_write(STACK+0x4000+(k-8)*8,struct.pack('<Q',v))
   u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr);u.emu_start(entry if ix==0 else sy['_ml_'+name],STOP,count=1000000)
   raw_return=u.reg_read(ac.UC_ARM64_REG_X0);assert raw_return==callargs[0],(name,case,ix,hex(raw_return),hex(callargs[0]))
   ret=displacement if use_alias else raw_return
   actual=(ret,bytes(u.mem_read(MEM,SIZE)),u.reg_read(ac.UC_ARM64_REG_FPCR),u.reg_read(ac.UC_ARM64_REG_FPSR),bytes(u.mem_read(g-256,1280)));assert u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x4000 and u.reg_read(ac.UC_ARM64_REG_PC)==STOP
   assert [u.reg_read(r) for r in preserved]==initial
   if ix==0:expected=actual;outcomes.add(ret)
   elif actual==expected:passes[ix-1]+=1;per[ix-1]+=1
   else:
    failure={'entry':hex(entry),'name':name,'case':case,'optimization':[0,2,3][ix-1],'original_return':expected[0],'source_return':ret,'original_fpsr':expected[3],'source_fpsr':actual[3],'memory_first_difference':next((i for i,(a,b) in enumerate(zip(expected[1],actual[1])) if a!=b),None),'args':list(map(hex,args)),'global_first_difference':next((i for i,(a,b) in enumerate(zip(expected[4],actual[4])) if a!=b),None),'global_data_hex':bytes(global_data).hex(),'global_alias':use_alias,'displacement':displacement,'memory_hex':bytes(data).hex(),'fpcr':hex(fpcr),'fpsr':hex(fpsr)};failures.append(failure);write(out/'FIRST_MISMATCH.json',failure);raise AssertionError(str({k:v for k,v in failure.items() if k!='memory_hex'}))
  if case%2048==0:write(out/'PROGRESS.json',{'name':name,'case':case,'passes':passes})
 loc=sorted(covered-before);assert len(loc)==n//4,(name,len(loc),n//4);assert len(tested_displacements)==30 and min(tested_displacements)==-128 and max(tested_displacements)==255
 rows.append({'image_sha256':image,'entry':hex(entry),'end_exclusive':hex(entry+n),'name':name,'original_bytes':n,'original_function_sha256':sha(read(entry,n)),'cases':cases,'comparisons':cases*3,'passes':per,'mismatches':0,'all_original_instructions_exercised':True,'original_instruction_locations':list(map(hex,loc)),'aliased_cases':aliases,'tested_alias_displacements':sorted(tested_displacements),'output_patterns':len(patterns),'return_outcomes':len(outcomes),'complete_function_bounded_test':True});write(out/'INTERMEDIATE.json',{'functions':rows,'failures':failures})
report={'image_sha256':image,'lane':lane,'table_checks':table_checks,'original_warning_queue_artifact_id':11862473419,'data_symbol':'__ZN6GImage12ms_ImportLUTE','compiled_prefix_guard_verified_zero_and_not_instruction_bytes':True,'compiled_prefix_guard_written':False,'x0_return_preserved_and_asserted_before_pointer_identity_normalization':True,'original_data_address':'0x474190','alias_scope':'source before/at/after shared destination, offsets-128..255; compiled prefix guard is verified zero non-instruction padding and never written','no_instruction_patch':True,'functions':rows,'complete_functions':len(rows),'original_bytes':sum(r['original_bytes'] for r in rows),'comparisons':sum(r['comparisons'] for r in rows),'passes':passes,'mismatches':0,'failures':failures,'source_sha256':sha(source.read_bytes()),'modules':modules,'native_imports':0,'native_callees':0,'native_stubs_used':False,'elapsed_seconds':time.time()-began,'limits':['Finite mapped ordinary-memory inputs and aliased public buffers only; not all-input proof.','No fault/MMIO/race or asynchronous observer equivalence.','Private stack alias inputs excluded.','Original high-level return type unknown; unchanged x0 is conservatively preserved and asserted in both executions before shared-data pointer identity normalization. All writes and guards compared without normalization.','Whole native image builds and Payload integration remain unresolved.']};write(out/'REPORT.json',report);print(json.dumps(report,indent=2))
