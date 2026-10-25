"""Two new flagged complete initializers: real symbols, exact original bytes, no callee stubs."""
import argparse,pathlib,hashlib,json,random,subprocess,time
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
P=pathlib.Path;sha=lambda x:hashlib.sha256(x).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--lane',choices=['logic','madsp'],required=True);lane=p.parse_args().lane
spec={'logic':('8dc0169c2d2bd0b15a48340a9f1c1508315cd33a2cce3f49704de5ba51734287',0x123dbc,52,0x15050d0,64,'__ZN9ScRastral18s_followStaffFloatE','logic_follow_staff_init',11870111501),'madsp':('8b7cbaa383d3050241921e74d1334b22703193afed6ea5e9388599cc42a60fe8',0x4f59b4,100,0x137a100,136,'__ZN18WrinkleAnalogShell16m_pFader2ParaMapE','madsp_fader_map_init',11878916555)}[lane]
image,entry,n,g,span,symbol,name,queue=spec;start=time.time();out=P('shared-init-'+lane);out.mkdir(exist_ok=True)
raw=P('prior/'+lane+'-input/target.bin').read_bytes();assert sha(raw)==image
segs,sections,starts,symbols=macho(raw);assert symbols[symbol]==g and starts[starts.index(entry)+1]==entry+n
sec=next(s for s in sections if s[1]<=g and g+span<=s[1]+s[2]);assert sec[0]=='__common' and sec[4]&255==1
assert min(v for v in symbols.values() if v>g)==g+span
accepted=json.loads(P('reconstruction/DEPENDENCY_CLOSURE_CHECKPOINT.json').read_text())['accepted_function_keys'];assert not any(r['image_sha256']==image and int(r['entry'],0)==entry for r in accepted)
def read(a,z):
 for _,v,sz,off,_ in sections:
  if v<=a and a+z<=v+sz:return raw[off+a-v:off+a-v+z]
 raise ValueError(a)
source=P('reconstruction/'+name+'.cpp');(out/source.name).write_bytes(source.read_bytes());STACK=0x40000000;STOP=0x50000000
preserved=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
def load(b,isref):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);sg,ss,st,sy=macho(b)
 for nm,v,z,off,fl in sg:
  if nm=='__PAGEZERO' or not z:continue
  lo=v&~4095;u.mem_map(lo,((v+z+4095)&~4095)-lo)
  if fl:u.mem_write(v,b[off:off+fl])
 u.mem_map(STACK,0x8000);u.mem_map(STOP,4096);dest=g if isref else sy[symbol];assert bytes(u.mem_read(dest,span))==bytes(span)
 # All stores outside the real symbol footprint or private stack fail; no write masking.
 def wr(uc,access,ad,size,val,data):assert dest<=ad and ad+size<=dest+span or STACK<=ad and ad+size<=STACK+0x8000,(hex(ad),size)
 u.hook_add(UC_HOOK_MEM_WRITE,wr);return u,entry if isref else sy['_ml_'+name],dest
engines=[load(raw,True)];build=[];modules=[]
for opt in [0,2,3]:
 obj=out/f'O{opt}.o';lib=out/f'O{opt}.dylib'
 cmds=[['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-std=c++17','-ffreestanding','-fno-builtin','-fno-exceptions','-fno-rtti','-fno-stack-protector','-c',str(source),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-no_fixup_chains','-dylib',str(obj),'-o',str(lib)]]
 for cmd in cmds:
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});write(out/'BUILD.json',build);assert r.returncode==0,r.stderr
 r=subprocess.run(['llvm-nm-18','--undefined-only',str(lib)],capture_output=True,text=True);assert not r.stdout.strip(),r.stdout
 engines.append(load(lib.read_bytes(),False));modules.append({'optimization':opt,'sha256':sha(lib.read_bytes())})
covered=set()
def hook(u,pc,size,data):assert entry<=pc<entry+n,hex(pc);covered.add(pc)
engines[0][0].hook_add(UC_HOOK_CODE,hook)
rng=random.Random(entry);cases=16384;passes=[0,0,0]
for case in range(cases):
 before=rng.randbytes(span);args=[rng.getrandbits(64) for _ in range(8)];saved=[rng.getrandbits(64) for _ in preserved];fpcr=((case//512)%4<<22)|((case//2048)%4<<24);fpsr=case*0x01010101&0xf800009f
 for ix,(u,pc,dest) in enumerate(engines):
  u.mem_write(dest,before);u.mem_write(STACK,b'\xa5'*0x8000)
  for i,v in enumerate(args):u.reg_write(getattr(ac,f'UC_ARM64_REG_X{i}'),v)
  for reg,v in zip(preserved,saved):u.reg_write(reg,v)
  u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,STOP);u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr)
  u.emu_start(pc,STOP,count=10000)
  actual=(bytes(u.mem_read(dest,span)),u.reg_read(ac.UC_ARM64_REG_X0),u.reg_read(ac.UC_ARM64_REG_FPCR),u.reg_read(ac.UC_ARM64_REG_FPSR));assert actual[1]==args[0] and u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x4000 and u.reg_read(ac.UC_ARM64_REG_PC)==STOP;assert [u.reg_read(r) for r in preserved]==saved
  if ix==0:expected=actual
  elif actual==expected:passes[ix-1]+=1
  else:
   write(out/'FIRST_MISMATCH.json',{'case':case,'optimization':[0,2,3][ix-1],'before':before.hex(),'expected':expected[0].hex(),'actual':actual[0].hex(),'x0':hex(args[0])});raise AssertionError('source mismatch')
 if case%2048==0:write(out/'PROGRESS.json',{'case':case,'passes':passes})
assert covered==set(range(entry,entry+n,4))
report={'image_sha256':image,'entry':hex(entry),'end_exclusive':hex(entry+n),'original_bytes':n,'original_function_sha256':sha(read(entry,n)),'source_sha256':sha(source.read_bytes()),'data_symbol':symbol,'data_address':hex(g),'data_span':span,'original_data_zero_initialized':True,'original_warning_queue_artifact_id':queue,'cases':cases,'comparisons':cases*3,'passes':passes,'mismatches':0,'all_original_instructions_exercised':True,'original_instruction_locations':list(map(hex,sorted(covered))),'complete_function_bounded_test':True,'native_callees':0,'native_imports':0,'modules':modules,'no_instruction_patch':True,'all_writes_checked_against_symbol_or_private_stack':True,'raw_x0_preserved':True,'elapsed_seconds':time.time()-start,'limits':['Finite ordinary stable mapped memory only; no all-input proof.','No concurrency/MMIO/fault/asynchronous observer guarantee.','Shared storage footprint and machine ABI recovered; full class declaration and original high-level return type remain uncertain.','Other shared-state users and whole-image integration remain unverified.']};write(out/'REPORT.json',report);print(json.dumps(report))
