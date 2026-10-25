"""New original-only dispatch execution; native calls stop before entry, never emulated by stubs."""
import pathlib,json,struct,hashlib,random
from unicorn import *
from unicorn import arm64_const as ac
from stage_batch_worker import macho,write
P=pathlib.Path;raw=P('auto-failure-dossiers/logic-input/target.bin').read_bytes();sg,se,starts,symbols=macho(raw);entry=0xe2d0c0;end=0xe2d1e4;assert starts[starts.index(entry)+1]==end
u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
for name,v,z,o,f in sg:
 if name=='__PAGEZERO' or not z:continue
 lo=v&~4095;u.mem_map(lo,((v+z+4095)&~4095)-lo)
 if f:u.mem_write(v,raw[o:o+f])
MEM=0x30000000;STACK=0x40000000;STOP=0x50000000;u.mem_map(MEM,0x4000);u.mem_map(STACK,0x8000);u.mem_map(STOP,4096)
# Independent byte-offset jump table -> actual tail destination, not synthetic aliases.
targets={1:0xe2f4d8,2:0xe2fc6c,3:0xe302d8,4:0xe30910,5:0xe30f48,6:0xe31580,7:0xe31bb8,8:0xe3208c,9:0xe32560,10:0xe32b80,11:0xe331a0};boundaries=set(targets.values())|{0xe2ecb0,0xf0ac2c};seen=set();observed=[]
def hook(uc,pc,size,data):
 if pc in boundaries:uc.emu_stop();return
 assert entry<=pc<end,hex(pc);seen.add(pc)
u.hook_add(UC_HOOK_CODE,hook);rng=random.Random(entry);regs=[getattr(ac,f'UC_ARM64_REG_X{i}') for i in range(19,30)]+[getattr(ac,f'UC_ARM64_REG_D{i}') for i in range(8,16)];counts={};cases=4096
for case in range(cases):
 genre=([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,0xffffffff]+[rng.getrandbits(32)])[case%17];flag=case//17%4;data=bytearray(rng.randbytes(0x4000));obj=MEM+0x100;out=MEM+0x1800;struct.pack_into('<I',data,0x298,genre);data[0x160]=flag;before=bytes(data);u.mem_write(MEM,before);u.mem_write(STACK,b'\xa5'*0x8000);saved=[rng.getrandbits(64) for _ in regs]
 for reg,val in zip(regs,saved):u.reg_write(reg,val)
 u.reg_write(ac.UC_ARM64_REG_X0,obj);u.reg_write(ac.UC_ARM64_REG_X1,0xdeadbeef);u.reg_write(ac.UC_ARM64_REG_X8,out);u.reg_write(ac.UC_ARM64_REG_X30,STOP);u.reg_write(ac.UC_ARM64_REG_SP,STACK+0x4000);u.reg_write(ac.UC_ARM64_REG_FPCR,0);u.reg_write(ac.UC_ARM64_REG_FPSR,0);u.emu_start(entry,STOP,count=1000)
 expected=targets.get(genre,STOP)
 if genre==12:expected=0xe2ecb0 if flag==2 else 0xf0ac2c if flag==1 else STOP
 pc=u.reg_read(ac.UC_ARM64_REG_PC);assert pc==expected,(genre,flag,hex(pc),hex(expected));actual=bytes(u.mem_read(MEM,0x4000));assert actual==before[:0x1800]+bytes(24)+before[0x1818:] if expected==STOP else actual==before
 assert u.reg_read(ac.UC_ARM64_REG_X8)==out
 if expected==0xf0ac2c:assert u.reg_read(ac.UC_ARM64_REG_X0)==obj+0x50 and u.reg_read(ac.UC_ARM64_REG_X1)==10 and u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x3fe0
 else:assert u.reg_read(ac.UC_ARM64_REG_X0)==obj and u.reg_read(ac.UC_ARM64_REG_SP)==STACK+0x4000 and [u.reg_read(r) for r in regs]==saved
 if expected==0xe2ecb0:assert u.reg_read(ac.UC_ARM64_REG_X1)==obj+0x38
 assert u.reg_read(ac.UC_ARM64_REG_FPCR)==0 and u.reg_read(ac.UC_ARM64_REG_FPSR)==0;counts[hex(pc)]=counts.get(hex(pc),0)+1
syms={hex(a):[name for name,v in symbols.items() if v==a] for a in boundaries|{0xe2d1e4,0xe2e72c}};report={'date_utc':'2026-10-25','image_sha256':hashlib.sha256(raw).hexdigest(),'entry':hex(entry),'end_exclusive':hex(end),'original_bytes':end-entry,'original_instruction_count':(end-entry)//4,'flagged_decompiler_instruction_count':17,'original_warning_queue_artifact_id':11881406780,'source_path':'reconstruction/logic_genre_tables_dispatch.cpp','source_sha256':hashlib.sha256(P('reconstruction/logic_genre_tables_dispatch.cpp').read_bytes()).hexdigest(),'original_executions':cases,'mismatches':0,'observed_stop_counts':counts,'original_instruction_locations_exercised':list(map(hex,sorted(seen))),'symbols':syms,'exact_predicate_import':{'stub':'0xf0ac2c','symbol':'__ZNK10CSemitones8HasIntvlEi','argument_x0':'object+0x50','argument_w1':10},'source_compiled':False,'complete_function_accepted':False,'new_accepted_functions':0,'limits':['Original-only dispatch/call-boundary preflight; not source differential equivalence.','Stops before actual helper/import body. No fake body or instruction patch.','Predicate returning continuations at0xe2d18c..0xe2d1e0 remain unexecuted.','Hidden-result24-byte layout inferred; full class/production dependencies unresolved.']};write(P('reconstruction/LOGIC_GENRE_DISPATCH_PREFLIGHT_20261025.json'),report);print(json.dumps(report,indent=2))
