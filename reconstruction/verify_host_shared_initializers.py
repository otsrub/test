"""Real compiled C++ host data semantics vs original ARM64 bytes; target ABI still pending."""
import ctypes,subprocess,pathlib,json,hashlib,random,time,struct
from unicorn import *
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
P=pathlib.Path;out=P('shared-init-host');out.mkdir(exist_ok=True);sha=lambda b:hashlib.sha256(b).hexdigest();results=[];began=time.time();build=[]
compiler=subprocess.run(['g++','--version'],capture_output=True,text=True,check=True).stdout
for lane,entry,n,g,span,sym,src in [('logic',0x123dbc,52,0x15050d0,64,'_ZN9ScRastral18s_followStaffFloatE','logic_follow_staff_init'),('madsp',0x4f59b4,100,0x137a100,136,'_ZN18WrinkleAnalogShell16m_pFader2ParaMapE','madsp_fader_map_init')]:
 raw=P('auto-failure-dossiers/'+lane+'-input/target.bin').read_bytes();sg,se,starts,symbols=macho(raw);assert starts[starts.index(entry)+1]==entry+n and symbols['_'+sym]==g;u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for name,v,z,o,f in sg:
  if name=='__PAGEZERO' or not z:continue
  lo=v&~4095;u.mem_map(lo,((v+z+4095)&~4095)-lo)
  if f:u.mem_write(v,raw[o:o+f])
 stack=0x40000000;stop=0x50000000;u.mem_map(stack,0x8000);u.mem_map(stop,4096);seen=set()
 def code(uc,pc,z,data):assert entry<=pc<entry+n;seen.add(pc)
 def wr(uc,access,ad,z,val,data):assert g<=ad and ad+z<=g+span
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,wr);libs=[];mods=[];source=P('reconstruction/'+src+'.cpp');(out/source.name).write_bytes(source.read_bytes())
 for opt in [0,2,3]:
  lib=out/f'{lane}-O{opt}.so';cmd=['g++','-std=c++17',f'-O{opt}','-fPIC','-shared','-fno-exceptions','-fno-rtti','-fno-stack-protector','-fno-builtin','-Wl,-Bsymbolic',str(source),'-o',str(lib)];r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);build.append({'argv':cmd,'returncode':r.returncode,'stderr':r.stderr});write(out/'BUILD.json',build);assert r.returncode==0,r.stderr
  nm=subprocess.run(['nm','-D','--undefined-only',str(lib)],capture_output=True,text=True,check=True).stdout;h=ctypes.CDLL(str(lib.resolve()));fn=getattr(h,'ml_'+src);fn.argtypes=[ctypes.c_uint64];fn.restype=ctypes.c_uint64;table=(ctypes.c_ubyte*span).in_dll(h,sym);assert bytes(table)==bytes(span);libs.append((h,fn,table));mods.append({'optimization':opt,'sha256':sha(lib.read_bytes()),'undefined_dynamic_symbols':nm,'architecture':'x86_64 ELF, host ABI not ARM64'})
 rng=random.Random(entry^0x725);cases=16384;passes=[0,0,0]
 regs=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)]
 for case in range(cases):
  before=rng.randbytes(span+256);x0=rng.getrandbits(64);saved=[rng.getrandbits(64) for _ in regs];fpcr=((case//512)%4<<22)|((case//2048)%4<<24);fpsr=(case*0x1010101)&0xf800009f
  u.mem_write(g-128,before)
  for reg,v in zip(regs,saved):u.reg_write(reg,v)
  u.reg_write(ac.UC_ARM64_REG_X0,x0);u.reg_write(ac.UC_ARM64_REG_X30,stop);u.reg_write(ac.UC_ARM64_REG_SP,stack+0x4000);u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr);u.emu_start(entry,stop,count=1000)
  expected=bytes(u.mem_read(g,span));assert bytes(u.mem_read(g-128,128))==before[:128] and bytes(u.mem_read(g+span,128))==before[128+span:];assert u.reg_read(ac.UC_ARM64_REG_X0)==x0 and u.reg_read(ac.UC_ARM64_REG_FPCR)==fpcr and u.reg_read(ac.UC_ARM64_REG_FPSR)==fpsr and [u.reg_read(r) for r in regs]==saved and u.reg_read(ac.UC_ARM64_REG_SP)==stack+0x4000
  for i,(h,fn,table) in enumerate(libs):
   ctypes.memmove(ctypes.addressof(table),before[128:128+span],span);returned=fn(x0);actual=bytes(table)
   if actual!=expected or returned!=x0:
    write(out/'FIRST_MISMATCH.json',{'lane':lane,'case':case,'optimization':[0,2,3][i],'prior':before.hex(),'expected':expected.hex(),'actual':actual.hex(),'x0':x0,'returned':returned});raise AssertionError('host-source mismatch')
   passes[i]+=1
  if case%2048==0:write(out/'PROGRESS.json',{'lane':lane,'case':case,'passes':passes})
 assert seen==set(range(entry,entry+n,4));results.append({'image':lane,'image_sha256':sha(raw),'entry':hex(entry),'end_exclusive':hex(entry+n),'original_bytes':n,'source_sha256':sha(source.read_bytes()),'cases':cases,'comparisons':cases*3,'passes':passes,'mismatches':0,'original_instruction_locations':len(seen),'modules':mods,'target_arm64_source_compiled':False,'target_abi_differential_tested':False,'complete_function_accepted':False})
report={'date_utc':'2026-10-25','compiler':compiler,'results':results,'new_cross_architecture_original_vs_compiled_comparisons':sum(r['comparisons'] for r in results),'mismatches':0,'new_accepted_functions':0,'elapsed_seconds':time.time()-began,'limits':['Actual native host C++ source execution, not target ARM64/iOS source execution.','Only table bytes and raw scalar x0 result cross-compared; ARM64 ABI/FP state checked on original only.','Original global guards checked; host global guards not allocated around exact symbol.','Host ELF source builds do not replace original binaries. ARM64 compilation, whole-image/shared-state integration pending.','Finite tests, not all-input proof.']};write(out/'REPORT.json',report);write(P('reconstruction/SHARED_INITIALIZERS_HOST_EVIDENCE_20261025.json'),report);print(json.dumps(report,indent=2))
