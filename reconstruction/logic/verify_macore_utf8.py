"""Execute the MACore clone independently; never reuse Logic's comparison result."""
from pathlib import Path
import hashlib,struct,json
root=Path.cwd();original=(root/'dossiers/macore-input/target.bin').read_bytes()
expected='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
assert hashlib.sha256(original).hexdigest()==expected
# Original compiler metadata must bound this exact 500-byte clone.
pos=32;stream=None;base=None
for _ in range(struct.unpack_from('<I',original,16)[0]):
 cmd,n=struct.unpack_from('<II',original,pos)
 if cmd==25 and original[pos+8:pos+24].split(b'\0')[0]==b'__TEXT':base=struct.unpack_from('<Q',original,pos+24)[0]
 if cmd==0x26:
  off,size=struct.unpack_from('<II',original,pos+8);stream=original[off:off+size]
 pos+=n
assert stream is not None and base is not None
starts=[];address=base;v=shift=0
for byte in stream:
 v|=(byte&127)<<shift
 if byte&128:shift+=7;continue
 if not v:break
 address+=v;starts.append(address);v=shift=0
idx=starts.index(0xce810);assert starts[idx+1]==0xcea04
assert hashlib.sha256(original[0xce810:0xcea04]).hexdigest()=='8b5474dbaf6b63af8648151611e93bbc3221c696dae23e24e50f57642b449ff3'
script=(root/'reconstruction/logic/verify_logic_utf8.py').read_text()
assert hashlib.sha256(script.encode()).hexdigest()=='006b25979a5e49c928e09575ed549fa2984dc1f076e71f070af152f028264b8c'
script=script.replace("dossiers/logic-input/target.bin","dossiers/macore-input/target.bin").replace('==EXPECTED_LOGIC',"=='"+expected+"'").replace('0x8ba1c0','0xce810').replace('0x8ba3b4','0xcea04').replace("'utf8-source'","'macore-utf8-source'")
exec(compile(script,__file__,'exec'))
p=root/'macore-utf8-source/verification.json';d=json.loads(p.read_text());d['clone_provenance']={'logic_run':39889659496,'logic_artifact':12473812739,'same_original_500_bytes':True,'independent_MACore_execution':True,'compiler_metadata_extent':['0xce810','0xcea04']};p.write_text(json.dumps(d,indent=2))
