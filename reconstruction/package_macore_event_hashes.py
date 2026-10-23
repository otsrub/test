import hashlib, json, pathlib, shutil, subprocess
root = pathlib.Path.cwd()
out = root / 'macore-event-hashes-source-package'
out.mkdir(exist_ok=True)
(out/'source').mkdir(exist_ok=True)
(out/'evidence').mkdir(exist_ok=True)
source = root/'reconstruction/macore_event_hashes.c'
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
reports = []
for lane in ('diff','method','fields'):
    folder = root/'hash-parents'/lane
    report_path = next(folder.rglob('verification.json'))
    r = json.loads(report_path.read_text())
    assert r['lane']==lane and r['mismatches']==0 and r['comparisons']==98304
    assert r['source_sha256']==source_sha and r['complete_function_bounded_test_accepted']
    reports.append(r)
    shutil.copy2(report_path,out/'evidence'/f'{lane}-verification.json')
shutil.copy2(source,out/'source'/source.name)
shutil.copy2(root/'reconstruction/verify_macore_event_hashes.py',out/'evidence')
shutil.copy2(root/'prior/verify_logic_tail_adapters.py',out/'evidence')
shutil.copy2(root/'dossiers/macore-input/target.bin',out/'evidence/original-MACore-reference.bin')
(out/'Makefile').write_text('''CLANG ?= clang-18
LINKER ?= ld64.lld-18
CFLAGS = -target arm64-apple-ios17.0 -O2 -ffreestanding -fno-builtin -fno-stack-protector -Wall -Wextra -Werror
all: build/macore-event-hashes.dylib
build/macore-event-hashes.dylib: source/macore_event_hashes.c
\tmkdir -p build
\t$(CLANG) $(CFLAGS) -c $< -o build/macore-event-hashes.o
\t$(LINKER) -arch arm64 -platform_version ios 17.0 17.0 -dylib -undefined error build/macore-event-hashes.o -o $@
clean:
\trm -rf build
''')
r = subprocess.run(['make','clean','all'],cwd=out,text=True,capture_output=True)
(out/'evidence/clean-build.log').write_text(r.stdout+r.stderr)
assert r.returncode==0,r.stderr
lib=out/'build/macore-event-hashes.dylib'
r=subprocess.run(['llvm-nm-18','--undefined-only',str(lib)],text=True,capture_output=True)
assert r.returncode==0 and not r.stdout.strip(),r.stdout+r.stderr
(out/'PROVENANCE.json').write_text(json.dumps({
 'source_sha256':source_sha,'module_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),
 'original_sha256':hashlib.sha256((out/'evidence/original-MACore-reference.bin').read_bytes()).hexdigest(),
 'parent_run':39952335477,'functions':3,'original_bytes':676,'comparisons':sum(r['comparisons'] for r in reports),'mismatches':0,'native_imports':0,
 'scope':'Clean standalone three-function source module with Makefile, reproduction evidence and original reference binary outside Payload; not MACore.framework replacement.',
 'all_input_equivalence_proven':False,'complete_native_images_rebuilt':0,
},indent=2)+'\n')
print((out/'PROVENANCE.json').read_text())
