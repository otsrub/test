"""New complete-function source tests for28MACore PNG metadata routines.
Actual original bytes, all public modeled memory, stack argument ABI and FPSR.
No decompiler/profile retry and no native callee stub.
"""
import argparse,hashlib,json,pathlib,random,struct,subprocess,time
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
p=argparse.ArgumentParser();p.add_argument('--lane',choices=['fields','dimensions','floating'],required=True);lane=p.parse_args().lane
out=pathlib.Path('png-metadata-'+lane);out.mkdir(exist_ok=True);began=time.time()
raw=pathlib.Path('prior/dependency-closure-dossier/MACore.original').read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest();image=sha(raw)
assert image=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
sg,sc,starts,symbols=macho(raw)
specs={'fields':[(0xf7010,56,'PLTE',8),(0xf6750,48,'bKGD',32),(0xf6c68,48,'hIST',64),(0xf7048,48,'sBIT',2),(0xf70bc,48,'tIME',512),(0xf6b6c,48,'sRGB',2048),(0xf6af8,48,'gAMA_fixed',1),(0xf6c30,56,'eXIf_1',65536),(0xf6d30,68,'oFFs',256),(0xf6b9c,80,'iCCP',4096),(0xf6f74,60,'sCAL_s',16384),(0xf69c8,160,'cHRM_XYZ_fixed',2),(0xf6a68,144,'cHRM_fixed',2),(0xf6d74,132,'pCAL',1024),(0xf6fb0,96,'pHYs',128),(0xf70ec,144,'tRNS',16),(0xf7078,68,'text',0)],'dimensions':[(0xf60b0,52,'x_pixels_per_meter',128),(0xf60e4,52,'y_pixels_per_meter',128),(0xf6118,48,'pixels_per_meter',128),(0xf6204,52,'x_offset_microns',256),(0xf6238,52,'y_offset_microns',256),(0xf626c,56,'x_offset_pixels',256),(0xf62a4,56,'y_offset_pixels',256)],'floating':[(0xf6b28,68,'gAMA',1),(0xf6148,48,'pixel_aspect_ratio',128),(0xf65f0,64,'x_offset_inches',256),(0xf6630,64,'y_offset_inches',256)]}[lane]
# Exact current accepted keys and separate candidate keys exclude duplicate work.
current=json.loads(pathlib.Path('reconstruction/DEPENDENCY_CLOSURE_CHECKPOINT.json').read_text());old={(f['image_sha256'],int(f['entry'],0)) for f in current['accepted_function_keys']}
gaps=json.loads(pathlib.Path('inventory/all-unsolved-dependencies/ACCEPTED_INDEX_GAPS.json').read_text());old|={(a,int(b,0)) for a,b in gaps['compiled_bounded_getter_candidate_keys']}
def read(a,n):
 for _,v,s,o,_ in sc:
  if v<=a and a+n<=v+s:return raw[o+a-v:o+a-v+n]
 raise ValueError(hex(a))
for a,n,name,mask in specs:assert (image,a) not in old and a in starts and starts[starts.index(a)+1]==a+n
source=pathlib.Path('reconstruction/macore_png_metadata_fields.c');(out/source.name).write_bytes(source.read_bytes())
MEM,STACK,STOP=0x30000000,0x40000000,0x50000000;SIZE=0x4000
build=[];modules=[];engines=[]
def load(b):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);segs,_,_,sy=macho(b)
 for name,va,vs,fo,fl in segs:
  if name=='__PAGEZERO' or not vs:continue
  lo,hi=va&~4095,(va+vs+4095)&~4095;u.mem_map(lo,hi-lo)
  if fl:u.mem_write(va,b[fo:fo+fl])
 u.mem_map(MEM,SIZE);u.mem_map(STACK,0x8000);u.mem_map(STOP,4096)
 return u,sy
for opt in (0,2,3):
 obj,lib=out/f'O{opt}.o',out/f'O{opt}.dylib'
 for cmd in [['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-ffp-contract=off','-frounding-math','-c',str(source),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-no_fixup_chains','-dylib',str(obj),'-o',str(lib)]]:
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});write(out/'BUILD.json',build);assert r.returncode==0,r.stderr
 r=subprocess.run(['llvm-nm-18','--undefined-only',str(lib)],capture_output=True,text=True,timeout=60);assert r.returncode==0 and not r.stdout.strip(),r.stdout
 u,sy=load(lib.read_bytes());engines.append((u,sy));modules.append({'optimization':opt,'sha256':sha(lib.read_bytes())})
ref,_=load(raw);covered=set();bounds=[(0,0)]
def hook(u,pc,size,_):
 assert bounds[0][0]<=pc<bounds[0][1],hex(pc);covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook)
# Resume only the never-completed field suffix; immutable prefix is preserved.
prefix=[]
if lane=='fields':
 prefix_path=pathlib.Path('failed-parent/png-metadata-fields/INTERMEDIATE.json')
 if prefix_path.exists():
  parent=json.loads(prefix_path.read_text());assert not parent['failures']
  prefix=parent['functions'];assert len(prefix)==7
  for row in prefix:assert row['mismatches']==0 and row['all_original_instructions_exercised'] and row['passes']==[row['cases']]*3
  done={int(row['entry'],0) for row in prefix};specs=[row for row in specs if row[0] not in done]
  more_path=pathlib.Path('second-parent/png-metadata-fields/INTERMEDIATE.json')
  if more_path.exists():
   more=json.loads(more_path.read_text());assert not more['failures'] and len(more['functions'])==8
   for row in more['functions']:assert row['mismatches']==0 and row['all_original_instructions_exercised'] and row['passes']==[row['cases']]*3
   prefix+=more['functions'];done={int(row['entry'],0) for row in prefix};specs=[row for row in specs if row[0] not in done]
   write(out/'PRESERVED_SECOND_PREFIX.json',{'artifact_id':12563509755,'artifact_sha256':'cac7f0e574da6fca763d8db48ed6a54c80a645f9d4fbbab9ca2db61a5de217fa','functions':more['functions'],'new_comparisons':0,'unchanged_source':True})
  write(out/'PRESERVED_PREFIX.json',{'artifact_id':12562819268,'artifact_sha256':'d8e439354cac6ef605aa64e51938a9963ad734ee9912ad90a6b9bc9445454e77','functions':prefix,'new_comparisons':0,'unchanged_source':True,'reason':'Original run stopped during fixture packing for the next function; completed prefix is not rerun.'})
preserved=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
rng=random.Random(0xf6a68);cases=4096 if lane!='floating' else 8192;passes=[0,0,0];failures=[];rows=[]
edges=[0,1,2,3,255,256,65535,65536,0x1000000,0x1000001,0x7ffffffe,0x7fffffff,0x80000000,0x80000001,0xfffffffe,0xffffffff]
for entry,n,name,mask in specs:
 bounds[0]=(entry,entry+n);before=set(covered);per=[0,0,0];aliases=0;returns={};patterns=set()
 for case in range(cases):
  info=MEM+0x100+(case&15);ctx=MEM+0x80;data=bytearray(rng.randbytes(SIZE));io=info-MEM
  flags=rng.getrandbits(32)|mask
  if case%16==2:flags&=~mask
  struct.pack_into('<I',data,io+8,flags)
  special=rng.getrandbits(16)|mask
  if case%16==2:special&=~mask
  struct.pack_into('<H',data,io+0x7e,special & 0xffff)
  # Only iCCP dereferences a payload pointer. Pair loads capture this pointer
  # before aliased outputs; its memory remains physically mapped in all cases.
  struct.pack_into('<Q',data,io+0x88,MEM+0x2800+(case&15))
  struct.pack_into('<I',data,io+0x94,edges[case%len(edges)] if case<2048 else rng.getrandbits(32))
  x=edges[case%len(edges)] if case<4096 else rng.getrandbits(32);y=edges[(case//len(edges))%len(edges)] if case<4096 else rng.getrandbits(32)
  if case&1:y=x
  struct.pack_into('<II',data,io+0xe0,x,y);struct.pack_into('<I',data,io+0x34,edges[(case//3)%len(edges)] if case<4096 else rng.getrandbits(32))
  struct.pack_into('<II',data,io+0xd4,x,y);data[io+0xe8]=case%4;data[io+0xdc]=(case//4)%4;data[io+0x25]=3 if (case//512)&1 else rng.randrange(16)
  pointers=[]
  for k in range(9):
   present=bool(case&(1<<k))
   if name in ['PLTE'] and k==1:present=True
   if name=='eXIf_1' and k==0:present=True
   if name=='sCAL_s' and k<3:present=True
   target=MEM+0x1000+32*k+(case&15)
   if case%4==0:target=info+rng.choice([8,0x18,0x20,0x34,0x38,0x50,0x58,0x7c,0x80,0x88,0x94,0xb8,0xd4,0xd8,0xe0,0xe4,0xec,0xf0,0x108,0x118,0x150]);aliases+=int(present)
   elif case%4==1 and k>0:target=pointers[0] or target;aliases+=int(present)
   pointers.append(target if present else 0)
  if case%16==0:ctx=0
  if case%16==1:info=0
  patterns.add(tuple(bool(p) for p in pointers))
  initial=[rng.getrandbits(64) for _ in preserved];fpcr=((case%4)<<22)|((case//4)%4<<24);fpsr=(case*0x01010101)&0xf800009f
  for ix,(u,sy) in enumerate([(ref,{})]+engines):
   u.mem_write(MEM,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x8000)
   for reg,value in zip(preserved,initial):u.reg_write(reg,value)
   u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,STOP)
   args=[ctx,info]+pointers
   for k,value in enumerate(args):
    if k<8:u.reg_write(getattr(ac,f'UC_ARM64_REG_X{k}'),value)
    else:u.mem_write(STACK+0x4000+(k-8)*8,struct.pack('<Q',value))
   u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr)
   u.emu_start(entry if ix==0 else sy['_ml_png_'+name],STOP,count=30000)
   ret=u.reg_read(ac.UC_ARM64_REG_S0) if name in ['pixel_aspect_ratio','x_offset_inches','y_offset_inches'] else u.reg_read(ac.UC_ARM64_REG_X0)
   actual=(ret,bytes(u.mem_read(MEM,SIZE)),u.reg_read(ac.UC_ARM64_REG_FPCR),u.reg_read(ac.UC_ARM64_REG_FPSR))
   if ix==0:expected=actual;returns[str(ret)]=returns.get(str(ret),0)+1
   else:
    ok=actual==expected and u.reg_read(ac.UC_ARM64_REG_PC)==STOP and u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x4000 and [u.reg_read(reg) for reg in preserved]==initial
    per[ix-1]+=int(ok);passes[ix-1]+=int(ok)
    if not ok and len(failures)<16:failures.append({'entry':hex(entry),'name':name,'case':case,'opt':(0,2,3)[ix-1],'return_expected':expected[0],'return_actual':actual[0],'memory_equal':actual[1]==expected[1],'fpcr_expected':expected[2],'fpcr_actual':actual[2],'fpsr_expected':expected[3],'fpsr_actual':actual[3]})
  # Preserve diagnostics before failure so the original rejected state survives.
  if failures and len(failures)==1:write(out/'FIRST_FAILURE_STATE.json',{'function':name,'case':case,'args':list(map(hex,args)),'fpcr':hex(fpcr),'fpsr':hex(fpsr),'memory_hex':bytes(data).hex()})
 loc=sorted(covered-before);assert len(loc)==n//4,(name,len(loc),n//4)
 rows.append({'image_sha256':image,'entry':hex(entry),'end_exclusive':hex(entry+n),'original_bytes':n,'original_function_sha256':sha(read(entry,n)),'name':name,'cases':cases,'comparisons':cases*3,'passes':per,'mismatches':cases*3-sum(per),'original_instruction_locations':list(map(hex,loc)),'all_original_instructions_exercised':True,'aliased_output_cases':aliases,'optional_output_patterns':len(patterns),'return_outcomes':len(returns),'complete_function_bounded_test':True})
 write(out/'INTERMEDIATE.json',{'functions':rows,'failures':failures})
report={'image_sha256':image,'lane':lane,'functions':rows,'complete_functions':len(rows),'original_bytes':sum(r['original_bytes'] for r in rows),'comparisons':sum(r['comparisons'] for r in rows),'passes':passes,'mismatches':sum(r['comparisons'] for r in rows)-sum(passes),'failures':failures,'source_sha256':sha(source.read_bytes()),'modules':modules,'native_imports':0,'native_callees':0,'native_stubs_used':False,'resumed_completed_prefix_functions':len(prefix),'resumed_completed_prefix_comparisons':sum(r['comparisons'] for r in prefix),'elapsed_seconds':time.time()-began,'limits':['Finite valid mapped ordinary memory only; no all-input equivalence proof.','Logical payload pointer values may be arbitrary when only returned, but physically read payload bytes remain mapped.','Aliased public output/info buffers and stack-passed pointer ABI covered; aliases with private ABI stack excluded.','Byte access widths/order, faults, MMIO, races and asynchronous observers not claimed equivalent.','Whole native-image and Payload integration remain open.']}
write(out/'REPORT.json',report);print(json.dumps(report,indent=2));assert not failures and report['mismatches']==0
