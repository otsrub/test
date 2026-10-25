"""Original-execution preflight only; NOT compiled-source differential acceptance."""
import pathlib,random,struct,json,hashlib,re,time
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
P=pathlib.Path;reports=[]
for lane,a,n,g,size in [('logic',0x123dbc,52,0x15050d0,64),('madsp',0x4f59b4,100,0x137a100,136)]:
 raw=P('auto-failure-dossiers/'+lane+'-input/target.bin').read_bytes();sg,se,st,sy=macho(raw);assert st[st.index(a)+1]==a+n;u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for name,v,z,o,f in sg:
  if name=='__PAGEZERO' or not z:continue
  low=v&~4095;u.mem_map(low,((v+z+4095)&~4095)-low)
  if f:u.mem_write(v,raw[o:o+f])
 stack=0x40000000;stop=0x50000000;u.mem_map(stack,0x8000);u.mem_map(stop,4096);seen=set()
 def code(uc,pc,z,_):assert a<=pc<a+n;seen.add(pc)
 def store(uc,access,ad,z,value,_):assert g<=ad and ad+z<=g+size,(hex(ad),z)
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,store)
 if lane=='logic':
  text=P('reconstruction/logic_follow_staff_init.cpp').read_text();bits=[int(x,16) for x in re.search(r'bits\[16\]=\{(.*?)\}',text)[1].split(',')];expected=struct.pack('<16I',*bits)
 else:expected=struct.pack('<17Q',*[x&((1<<64)-1) for x in [-1,-1,0,1,2,3,4,5,-1,6,7,8,9,10,11,-1,12]])
 regs=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)];rng=random.Random(a)
 for case in range(4096):
  prior=rng.randbytes(size+256);u.mem_write(g-128,prior);args=[rng.getrandbits(64) for _ in range(8)];pres=[rng.getrandbits(64) for _ in regs]
  for i,v in enumerate(args):u.reg_write(getattr(ac,f'UC_ARM64_REG_X{i}'),v)
  for r,v in zip(regs,pres):u.reg_write(r,v)
  fpcr=((case//256)%4<<22)|((case//1024)%4<<24);fpsr=(case*0x1010101)&0xf800009f;u.reg_write(ac.UC_ARM64_REG_FPCR,fpcr);u.reg_write(ac.UC_ARM64_REG_FPSR,fpsr);u.reg_write(ac.UC_ARM64_REG_SP,stack+0x4000);u.reg_write(ac.UC_ARM64_REG_X30,stop);u.emu_start(a,stop,count=1000)
  assert bytes(u.mem_read(g-128,size+256))==prior[:128]+expected+prior[128+size:];assert u.reg_read(ac.UC_ARM64_REG_X0)==args[0];assert u.reg_read(ac.UC_ARM64_REG_FPCR)==fpcr and u.reg_read(ac.UC_ARM64_REG_FPSR)==fpsr;assert [u.reg_read(r) for r in regs]==pres;assert u.reg_read(ac.UC_ARM64_REG_SP)==stack+0x4000 and u.reg_read(ac.UC_ARM64_REG_PC)==stop
 assert seen==set(range(a,a+n,4));reports.append({'image':lane,'image_sha256':hashlib.sha256(raw).hexdigest(),'entry':hex(a),'bytes':n,'original_executions':4096,'instruction_locations':len(seen),'mismatches':0,'guard_bytes_compared':256,'expected_table_hex':expected.hex(),'compiled_source_tested':False,'complete_function_accepted':False})
write(P('reconstruction/SHARED_INITIALIZERS_PREFLIGHT_20261025.json'),{'date_utc':'2026-10-25','results':reports,'new_accepted_functions':0,'blocker':'Workflow file upload protocol rejected by browser URL policy; supported GitHub contents API returned403. Source and verifier saved, compiled execution pending.','limits':['Original execution against literal/source-bit model only, not compiled-source equivalence.','Full shared-state/class integration, original high-level return type unresolved.']});print(json.dumps(reports))
