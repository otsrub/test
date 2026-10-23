"""Assemble and clean-build actual source outside any Payload tree."""
import pathlib,shutil,json,hashlib,subprocess,os,struct
ROOT=pathlib.Path.cwd();out=ROOT/'madsp-purge-source-package';out.mkdir(exist_ok=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
reports=[]
for lane in ('duplicates','stale'):
 p=ROOT/'parents'/lane/f'madsp-purge-{lane}'/'verification.json';r=json.loads(p.read_text());assert r['comparisons']==49152 and r['mismatches']==0 and r['complete_function_bounded_test'];reports.append(r)
 (out/'evidence').mkdir(exist_ok=True);shutil.copy2(p,out/'evidence'/f'{lane}.json')
for src in ['reconstruction/madsp_purge_duplicates.c','reconstruction/madsp_purge_stale.c','reconstruction/verify_madsp_purge_duplicates.py','prior/verify_logic_tail_adapters.py','dossiers/madsp-input/target.bin']:
 p=out/src;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/src,p)
assert sha((out/'dossiers/madsp-input/target.bin').read_bytes())=='8b7cbaa383d3050241921e74d1334b22703193afed6ea5e9388599cc42a60fe8'
for lane,report in zip(('duplicates','stale'),reports):assert sha((out/f'reconstruction/madsp_purge_{lane}.c').read_bytes())==report['source_sha256']
(out/'Makefile').write_text('''CC = clang-18
LD = ld64.lld-18
CFLAGS = -target arm64-apple-ios17.0 -O2 -ffreestanding -fno-builtin -fno-stack-protector -Wall -Wextra -Werror
OBJECTS = build/duplicates.o build/stale.o
all: build/madsp-purge.dylib
build:
\tmkdir -p build
build/duplicates.o: reconstruction/madsp_purge_duplicates.c | build
\t$(CC) $(CFLAGS) -c $< -o $@
build/stale.o: reconstruction/madsp_purge_stale.c | build
\t$(CC) $(CFLAGS) -c $< -o $@
build/madsp-purge.dylib: $(OBJECTS)
\t$(LD) -arch arm64 -platform_version ios 17.0 17.0 -dylib -undefined error $(OBJECTS) -o $@
verify:
\tREA_LANE=duplicates python reconstruction/verify_madsp_purge_duplicates.py
\tREA_LANE=stale python reconstruction/verify_madsp_purge_duplicates.py
clean:
\trm -rf build
.PHONY: all verify clean
''')
r=subprocess.run(['make','clean','all'],cwd=out,text=True,capture_output=True);(out/'BUILD.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
# Reuse only the original-image mapping definitions; no original executable is linked.
parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();namespace={'__file__':str(ROOT/'prior/verify_logic_tail_adapters.py')};exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')],namespace)
raw=(out/'build/madsp-purge.dylib').read_bytes();_,symbols=namespace['macho'](raw);undefined=[name for name,value,undef in symbols if undef];assert not undefined,undefined
for name in ['_madsp_purge_duplicates','_madsp_purge_stale']:assert any(n==name and not undef for n,value,undef in symbols)
manifest={str(p.relative_to(out)):{'size':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(out.rglob('*')) if p.is_file()}
(out/'PROVENANCE.json').write_text(json.dumps({'commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'original_image_sha256':reports[0]['image_sha256'],'original_function_bytes':sum(r['original_function_bytes'] for r in reports),'parent_comparisons':sum(r['comparisons'] for r in reports),'parent_mismatches':0,'clean_source_build':True,'native_undefined_symbols':undefined,'module_sha256':sha(raw),'files':manifest,'scope':'Two real functions compiled together from source; reference original binary is evidence outside Payload and is never linked into the source-built module. This is not a MADSP framework replacement, full application build or universal equivalence proof.','limitations':reports[0]['limits']+reports[1]['limits']},indent=2))
(out/'README.md').write_text('Two recovered MADSP functions with bounded original-execution evidence.\n\nRun `make clean all` with clang-18/lld-18. To reproduce tests, install unicorn==2.1.4 and run `make verify`.\n\nThe original reference image is evidence only. Nothing here is an assembled Payload or full framework replacement.\n')
print(json.dumps({'module_sha256':sha(raw),'original_function_bytes':476,'comparisons':98304,'mismatches':0,'undefined_symbols':undefined},indent=2))
