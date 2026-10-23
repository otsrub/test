"""Create a standalone six-function source package only after all six evidence lanes pass."""
from pathlib import Path
import json,hashlib,shutil,subprocess,os,struct
root=Path.cwd();out=root/'integer-digits-source-package';out.mkdir(exist_ok=True)
def sha(b):return hashlib.sha256(b).hexdigest()
source=(root/'reconstruction/logic/logic_integer_digits.c').read_bytes();sourcehash=sha(source)
expected={'binary':('0x8c0eec',160),'octal':('0x8c0f8c',172),'hex':('0x8c1038',164),'count':('0x8c10dc',104),'decimal':('0x8b8cd0',992),'generic':('0x8c0d8c',352)};reports=[];keys=set()
for lane,(entry,nbytes) in expected.items():
 p=root/'verified'/f'rea-integer-digits-{lane}-evidence'/f'integer-digits-{lane}'/'verification.json';r=json.loads(p.read_text())
 assert r['entry']==entry and r['original_bytes']==nbytes and r['mismatches']==0 and r['complete_function_bounded_tests_passed'] and not r['all_input_equivalence_proven'] and r['source_sha256']==sourcehash and r['cases']==32768 and r['comparisons']==98304
 key=(r['image_sha256'],r['entry']);assert key not in keys;keys.add(key);reports.append(r)
assert len(keys)==6
for name in ['tests','prior','dossiers/logic-input','evidence','build']:(out/name).mkdir(parents=True,exist_ok=True)
(out/'logic_integer_digits.c').write_bytes(source)
test=(root/'reconstruction/logic/verify_logic_integer_digits.py').read_text().replace("ROOT/'reconstruction/logic/logic_integer_digits.c'","ROOT/'logic_integer_digits.c'");(out/'tests/verify_logic_integer_digits.py').write_text(test)
parent=(root/'prior/verify_logic_tail_adapters.py').read_bytes();assert sha(parent)=='c7e09be891a5cf7c1ab3df11dddb6066bb41acd674fb3f8125c5719cf9316747';(out/'prior/verify_logic_tail_adapters.py').write_bytes(parent)
original=(root/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)=='8dc0169c2d2bd0b15a48340a9f1c1508315cd33a2cce3f49704de5ba51734287';(out/'dossiers/logic-input/target.bin').write_bytes(original)
for r in reports:(out/'evidence'/f"{r['lane']}-verification.json").write_text(json.dumps(r,indent=2)+'\n')
make='''CC := clang-18
LD := ld64.lld-18
IOS_VERSION ?= 17.0
CFLAGS := -target arm64-apple-ios$(IOS_VERSION) -O2 -ffreestanding -fno-builtin -fno-stack-protector -Wall -Wextra -Werror
all: build/logic_integer_digits.dylib
build:
\tmkdir -p build
build/logic_integer_digits.o: logic_integer_digits.c | build
\t$(CC) $(CFLAGS) -c $< -o $@
build/logic_integer_digits.dylib: build/logic_integer_digits.o
\t$(LD) -arch arm64 -platform_version ios $(IOS_VERSION) $(IOS_VERSION) -dylib -undefined error $< -o $@
verify:
\tfor lane in binary octal hex count decimal generic; do REA_LANE=$$lane python tests/verify_logic_integer_digits.py || exit $$?; done
.PHONY: all verify
'''
(out/'Makefile').write_text(make);(out/'requirements.txt').write_text('unicorn==2.1.4\n')
readme='''# Six original Logic digit-conversion functions

`make` builds a standalone ARM64 iOS source module with no unresolved imports. It does not rebuild the original Logic binary or any Payload tree.

The six entry-to-return suites each compared 32768 states at O0/O2/O3 against original executable bytes. See evidence for individual return/ABI/memory checks, original slice hashes and domain limits. Valid bases are 2..36; pointers reference ordinary mapped memory, and decimal output storage must have at least 10 physical bytes. Finite tests do not prove all-input equivalence.

Requirements: clang-18, lld-18, make, Python 3.12; `pip install -r requirements.txt` only for rerunning tests. Run `make verify` to explicitly rerun all suites. Original reference bytes, test helpers and reports live outside any Payload and are never counted as recovered source.
'''
(out/'README.md').write_text(readme)
r=subprocess.run(['make'],cwd=out,text=True,capture_output=True);(out/'build/build.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
# Inspect the fresh linked module with only the metadata parser (not another suite).
s=(root/'reconstruction/logic/verify_logic_integer_digits.py').read_text();scope={'struct':struct};exec(s[s.index('def metadata('):s.index('_,starts=metadata(original)')],scope);imports,_=scope['metadata']((out/'build/logic_integer_digits.dylib').read_bytes());assert not imports
provenance={'repository':'otsrub/test','commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'original_image_sha256':sha(original),'source_sha256':sourcehash,'clean_build_module_sha256':sha((out/'build/logic_integer_digits.dylib').read_bytes()),'complete_function_bounded_test_keys':[{'image_sha256':x[0],'entry':x[1]} for x in sorted(keys)],'original_bytes_across_six_functions':sum(r['original_bytes'] for r in reports),'comparisons':sum(r['comparisons'] for r in reports),'mismatches':0,'unresolved_imports':imports,'whole_logic_binary_rebuilt':False,'whole_payload_rebuilt':False,'all_input_equivalence_proven':False,'case_limits':'See individual evidence reports and README.','parent_utility_sha256':sha(parent)}
(out/'PROVENANCE.json').write_text(json.dumps(provenance,indent=2)+'\n')
with (out/'SHA256SUMS').open('w') as f:
 for p in sorted(out.rglob('*')):
  if p.is_file() and p.name!='SHA256SUMS':f.write(sha(p.read_bytes())+'  '+str(p.relative_to(out))+'\n')
print(json.dumps(provenance,indent=2))
