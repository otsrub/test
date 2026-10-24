"""Original error-chain call boundaries. No external system callee executes.
The callback_return lane executes a controlled actual native setter callback.
These are call-boundary phases, never complete-function or runtime closure tests.
"""
import argparse,hashlib,json,pathlib,random,struct,subprocess,time
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
P=pathlib.Path;sha=lambda b:hashlib.sha256(b).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--lane',choices=['error','default','longjmp','callback_return'],required=True);lane=p.parse_args().lane
real_callback=lane=='callback_return'
spec={'callback_return':(0x46fcc,'_ml_png_error_candidate'),'error':(0x46fcc,'_ml_png_error_candidate'),'default':(0x46ffc,'_ml_png_default_error_candidate'),'longjmp':(0x47054,'_ml_png_longjmp_candidate')}[lane]
out=P('png-error-'+lane);out.mkdir(exist_ok=True);began=time.time()
raw=P('prior/dependency-closure-dossier/MACore.original').read_bytes();image=sha(raw);assert image=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
source=P('reconstruction/macore_png_error_chain_candidates.c');(out/source.name).write_bytes(source.read_bytes());assert sha(source.read_bytes())=='1e45d876a0268ee02e36828b80405b61995e580e3558c9020778915ef18d2b4b'
def indirect(b):
 ncmd=struct.unpack_from('<I',b,16)[0];off=32;ss=[];sym=None;dy=None
 for _ in range(ncmd):
  cmd,size=struct.unpack_from('<II',b,off)
  if cmd==2:sym=struct.unpack_from('<IIII',b,off+8)
  if cmd==11:dy=struct.unpack_from('<II',b,off+56)
  if cmd==25:
   ns=struct.unpack_from('<I',b,off+64)[0]
   for k in range(ns):
    pos=off+72+k*80;name=b[pos:pos+16].split(b'\0')[0].decode();a,n=struct.unpack_from('<QQ',b,pos+32);flags,first,stride=struct.unpack_from('<III',b,pos+64);ss.append((name,a,n,flags&255,first,stride))
  off+=size
 assert sym and dy
 syoff,nsy,stroff,strsize=sym;indoff,nind=dy;names=[]
 for k in range(nsy):
  idx=struct.unpack_from('<I',b,syoff+k*16)[0];end=b.find(b'\0',stroff+idx,stroff+strsize);names.append(b[stroff+idx:end].decode())
 stubs={};pointers={}
 for name,a,n,typ,first,stride in ss:
  if typ not in (6,7,8):continue
  stride=stride if typ==8 else 8
  for k in range(n//stride):
   idx=struct.unpack_from('<I',b,indoff+4*(first+k))[0]
   if idx&0xc0000000:continue
   assert idx<nsy
   (stubs if typ==8 else pointers)[a+k*stride]=names[idx]
 return stubs,pointers
MEM,STACK,CALL=0x30000000,0x40000000,0x60000000;SIZE=0x4000
engines=[];modules=[];build=[];bindings=[];coverage=[];events=[];callback_targets=[];fixture_object=[0]
helper=P('reconstruction/macore_png_color_transform.c')
if real_callback:
 assert sha(helper.read_bytes())=='8ec4a7aee5625b1198d3eecad60b80351e889063939a0759da7cf75df62abd6b'
 (out/helper.name).write_bytes(helper.read_bytes())
def load(b,original=False):
 segs,sections,starts,sy=macho(b);u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for name,a,n,o,fl in segs:
  if name=='__PAGEZERO' or not n:continue
  lo=a&~4095;hi=(a+n+4095)&~4095;u.mem_map(lo,hi-lo)
  if fl:u.mem_write(a,b[o:o+fl])
 u.mem_map(MEM,SIZE);u.mem_map(STACK,0x8000)
 stubs,ptr=indirect(b);slots=[a for a,s in ptr.items() if s=='___stderrp'];assert slots
 for a in slots:u.mem_write(a,struct.pack('<Q',MEM+0x80))
 assert {'_fprintf','_abort'}<=set(stubs.values())
 if original:assert stubs[0x104be4]=='_fprintf' and stubs[0x104938]=='_abort' and ptr[0x15ce18]=='___stderrp'
 bindings.append({'original':original,'stderr_import_data_slots':list(map(hex,slots)),'bound_to_fixture_global':hex(MEM+0x80),'external_functions_bound_or_faked':False})
 loc=set();ev=[None];callback_target=(0x100a88 if original else sy['_ml_png_set_shift']) if real_callback else CALL;callback_targets.append(callback_target)
 def cstring(p):
  result=bytearray()
  for k in range(512):
   v=bytes(u.mem_read(p+k,1))
   if v==b'\0':return bytes(result).hex()
   result+=v
  raise AssertionError('unterminated test string')
 def stop(kind):
  x0=u.reg_read(ac.UC_ARM64_REG_X0);x1=u.reg_read(ac.UC_ARM64_REG_X1);sp=u.reg_read(ac.UC_ARM64_REG_SP)
  if kind=='_fprintf':
   mp=struct.unpack('<Q',bytes(u.mem_read(sp,8)))[0];assert mp
   args={'file_pointer':hex(x0),'format_bytes':cstring(x1),'variadic_message_bytes':cstring(mp)}
  elif kind=='_abort':args={}
  elif kind=='error_callback':args={'object':hex(x0),'message_pointer':hex(x1)}
  else:args={'jump_buffer':hex(x0),'integer_argument_low32':x1&0xffffffff}
  public=bytearray(u.mem_read(MEM,SIZE))
  if real_callback:
   off=fixture_object[0]-MEM+0xd8;assert struct.unpack_from('<Q',public,off)[0]==callback_target
   struct.pack_into('<Q',public,off,CALL) # comparison-only code-pointer identity normalization
  ev[0]={'kind':kind,'arguments':args,'public_memory_hex':bytes(public).hex(),'fpcr':u.reg_read(ac.UC_ARM64_REG_FPCR),'fpsr':u.reg_read(ac.UC_ARM64_REG_FPSR)};u.emu_stop()
 def hook(u,pc,n,_):
  if pc in stubs:
   assert stubs[pc] in ('_fprintf','_abort'),stubs[pc];stop(stubs[pc]);return
  if original:assert 0x46fcc<=pc<0x47078 or (real_callback and 0x100a88<=pc<0x100ab0),hex(pc)
  else:assert any(a<=pc<a+sz for _,a,sz,_,flags in sections if flags&0x80000400 and flags&255!=8),hex(pc)
  loc.add(pc);word=struct.unpack('<I',bytes(u.mem_read(pc,4)))[0]
  if word&0xfffffc1f in (0xd63f0000,0xd61f0000):
   rn=(word>>5)&31;target=u.reg_read(getattr(ac,f'UC_ARM64_REG_X{rn}'))
   if target==CALL:stop('error_callback' if lane=='error' else 'jump_callback')
 u.hook_add(UC_HOOK_CODE,hook);coverage.append(loc);events.append(ev);return u,sy
ref=load(raw,True)
for opt in (0,2,3):
 obj,lib=out/f'O{opt}.o',out/f'O{opt}.dylib'
 helper_obj=out/f'helperO{opt}.o'
 if real_callback:
  cmd=['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffp-contract=off','-frounding-math','-c',str(helper),'-o',str(helper_obj)];r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});assert r.returncode==0,r.stderr
 for cmd in [['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-c',str(source),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-no_fixup_chains','-undefined','dynamic_lookup','-dylib',str(obj),*([str(helper_obj)] if real_callback else []),'-o',str(lib)]]:
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});write(out/'BUILD.json',build);assert r.returncode==0,r.stderr
 engines.append(load(lib.read_bytes()));modules.append({'optimization':opt,'sha256':sha(lib.read_bytes())})
rng=random.Random(spec[0]);cases=4096;passes=[0,0,0];counts={};samples={};edges=[0,1,0x7fffffff,0x80000000,0xffffffff,255,256,0x12345678]
for case in range(cases):
 data=bytearray(rng.randbytes(SIZE));obj=MEM+0x100+(case&15);io=obj-MEM;ctx=0 if case%8==0 else obj;msg=0 if case%5==0 else MEM+0x1000+(case&7);value=edges[case%len(edges)] if case<2048 else rng.getrandbits(32)
 if real_callback:ctx=obj;msg=MEM+0x1000+(case&7)
 fixture_object[0]=obj
 if msg:
  text=rng.choice([b'',b'error',b'#123 text',b'\xff\x80raw',b'a'*63]);start=msg-MEM;data[start:start+len(text)+1]=text+b'\0'
 struct.pack_into('<Q',data,0x80,0 if case%13==0 else MEM+0x2800+(case&15));struct.pack_into('<Q',data,io+0xd8,CALL if case&1 else 0);struct.pack_into('<Q',data,io+0xc0,CALL if case&1 else 0);struct.pack_into('<Q',data,io+0xc8,MEM+0x1800+(case&31) if case&2 else 0)
 fpcr=((case%4)<<22)|((case//4)%4<<24);fpsr=(case*0x01010101)&0xf800009f
 for ix,(u,sy) in enumerate([ref]+engines):
  events[ix][0]=None;u.mem_write(MEM,bytes(data))
  if real_callback:u.mem_write(obj+0xd8,struct.pack('<Q',callback_targets[ix]))
  u.mem_write(STACK,bytes([0xa5])*0x8000);u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,0x70000000);u.reg_write(ac.UC_ARM64_REG_X0,ctx);u.reg_write(ac.UC_ARM64_REG_X1,value if lane=='longjmp' else msg);u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr)
  u.emu_start(spec[0] if ix==0 else sy[spec[1]],0x70000000,count=30000);actual=events[ix][0];assert actual is not None
  if ix==0:expected=actual;counts[actual['kind']]=counts.get(actual['kind'],0)+1;samples.setdefault(actual['kind'],{k:v for k,v in actual.items() if k!='public_memory_hex'})
  elif actual==expected:passes[ix-1]+=1
  else:
   f={'case':case,'optimization':[0,2,3][ix-1],'lane':lane,'original':expected,'source':actual,'initial_public_memory_hex':bytes(data).hex()};write(out/'FIRST_MISMATCH.json',f);raise AssertionError(str({k:v for k,v in f.items() if k not in ('original','source','initial_public_memory_hex')}))
assert passes==[cases]*3
if real_callback:
 assert counts=={'_fprintf':cases}
 assert set(range(0x100a88,0x100ab0,4))<=coverage[0]
report={'status':('actual native callback return and error-to-default path through first fprintf verified' if real_callback else 'first real dependency call boundary verified; no dependency callee body executed'),'lane':lane,'original_entry':hex(spec[0]),'source_entry_symbol':spec[1],'original_image_sha256':image,'source_sha256':sha(source.read_bytes()),'cases':cases,'comparisons':cases*3,'passes':passes,'mismatches':0,'original_instruction_locations':list(map(hex,sorted(coverage[0]))),'boundary_counts':counts,'boundary_samples':samples,'modules':modules,'import_data_fixture_bindings':bindings,'fake_callees':False,'patched_instructions':False,'real_dependency_callee_bodies_executed':(1 if real_callback else 0),'external_system_callee_bodies_executed':0,'controlled_returning_native_callback':({'original_entry':'0x100a88','source_symbol':'_ml_png_set_shift','source_sha256':sha(helper.read_bytes()),'source_and_original_bodies_actually_executed':True,'native_callback_instruction_locations':list(map(hex,range(0x100a88,0x100ab0,4))),'code_pointer_normalization':'Only unchanged callback slot0xd8 is mapped to a common identity in comparison output. Actual execution uses each real native/source function address.','callback_addresses':list(map(hex,callback_targets)),'production_callback_identity_claimed':False,'abi_assumption':'Chosen implementations accept two pointer arguments in AAPCS64 registers; production callback semantics not claimed.'} if real_callback else None),'complete_functions_accepted':0,'all_input_proof':False,'elapsed_seconds':time.time()-began,'limits':[('Controlled real native and compiled setter callback executes and returns, then stops before fprintf. No production callback-identity claim.' if real_callback else 'Stops before executing first callback, fprintf or abort. No fake dependency implementation.'),('The real original png_error invokes the chosen native callback body, accepts its return, restores arguments and enters its real default-error path.' if real_callback else 'The real original png_error to default-error transition executes when error callback is absent.'),'Only stderr import data slots are initialized to a synthetic allocated entry-state global; no instructions patched.','Compares actual call selection, callback integer/pointer arguments, Darwin variadic stack argument bytes, public memory, FPCR/FPSR.','Actual stdio FILE validity, production callbacks, longjmp/nonlocal returns and abort runtime behavior remain unverified.','Private stack-frame shape and callee-saved registers at an interior boundary are not equated.','No full-function, whole native-image or Payload acceptance follows.']};write(out/'REPORT.json',report);print(json.dumps(report,indent=2))
