"""Clean-build unique source modules from the four immutable getter batches."""
import collections
import hashlib
import json
import pathlib
import subprocess

root = pathlib.Path('stage-source-packages')
root.mkdir(exist_ok=True)
groups = collections.defaultdict(list)
seen = set()
parents = []
for report in sorted(pathlib.Path('parents').rglob('BATCH_REPORT.json')):
    batch = json.loads(report.read_text())
    assert batch['stage'] == 'verify' and batch['selected_targets'] == 16
    parents.append({'report': str(report), 'sha256': hashlib.sha256(report.read_bytes()).hexdigest()})
    for row in batch['results']:
        key = (row['image_sha256'], int(row['address'], 16))
        assert key not in seen, 'Duplicate original function key'
        seen.add(key)
        assert row['mismatches'] == 0 and row['passes'] == [row['cases']] * 3
        assert row['original_bytes'] == 8 and len(row['original_instruction_locations']) == 2
        src = report.parent / row['image_sha256'][:12] / row['address'] / 'recovered.c'
        raw = src.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row['source_sha256']
        groups[(row['image_sha256'], row['original_path'])].append((row, raw.decode()))
assert len(seen) == 64 and len(parents) == 4
manifest = []
for (digest, original_path), rows in sorted(groups.items()):
    dest = root / digest
    (dest / 'src').mkdir(parents=True, exist_ok=True)
    functions = []
    for row, source in sorted(rows, key=lambda x: int(x[0]['address'], 16)):
        symbol = 'mobilelogic_' + digest[:12] + '_' + row['address'][2:]
        assert source.count('u64 recovered(') == 1
        source = source.replace('u64 recovered(', 'u64 ' + symbol + '(')
        path = dest / 'src' / (row['address'] + '.c')
        path.write_text(source)
        functions.append({**row, 'package_symbol': symbol,
                          'package_source': str(path.relative_to(dest)),
                          'package_source_sha256': hashlib.sha256(source.encode()).hexdigest()})
    makefile = ('CC := clang-18\nLD := ld64.lld-18\n'
                'CFLAGS := -target arm64-apple-ios17.0 -O2 -ffreestanding -fno-builtin '
                '-fno-stack-protector -Wall -Wextra -Werror\n'
                'SOURCES := $(wildcard src/*.c)\nOBJECTS := $(SOURCES:src/%.c=build/%.o)\n'
                'all: build/recovered-getters.dylib\n'
                'build/%.o: src/%.c\n\tmkdir -p build\n\t$(CC) $(CFLAGS) -c $< -o $@\n'
                'build/recovered-getters.dylib: $(OBJECTS)\n'
                '\t$(LD) -arch arm64 -platform_version ios 17.0 17.0 -dylib $(OBJECTS) -o $@\n'
                '.PHONY: all\n')
    (dest / 'Makefile').write_text(makefile)
    build = subprocess.run(['make', '-C', str(dest)], capture_output=True, text=True, timeout=120)
    (dest / 'BUILD.log').write_text(build.stdout + build.stderr)
    assert build.returncode == 0, build.stderr
    # Strict linker invocation rejects unresolved native imports.
    module = dest / 'build/recovered-getters.dylib'
    record = {'original_path': original_path, 'original_image_sha256': digest,
              'complete_getter_candidates': len(rows), 'original_bytes': len(rows) * 8,
              'parent_comparisons': sum(r['comparisons'] for r, _ in rows),
              'parent_mismatches': 0, 'functions': functions,
              'module_sha256': hashlib.sha256(module.read_bytes()).hexdigest(),
              'native_imports': 0, 'clean_build': True,
              'combined_module_runtime_verified': False,
              'whole_original_image_rebuilt': False}
    (dest / 'MANIFEST.json').write_text(json.dumps(record, indent=2) + '\n')
    manifest.append(record)
result = {'kind': 'Seven clean per-image getter source subset packages',
          'original_functions': 64, 'original_bytes': 512, 'parents': parents,
          'parent_comparisons': 196608, 'parent_mismatches': 0, 'images': manifest,
          'whole_images_rebuilt': 0, 'payload_assembly': False,
          'limits': ['Renamed uniquely for linking; combined modules clean-built but not executed.',
                     'Parent differential evidence covers ordinary valid memory only.',
                     'No original executable bytes copied into source modules; no Payload produced.',
                     'Return types and original class interfaces require integration review.']}
(root / 'SUMMARY.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: result[k] for k in ('original_functions', 'original_bytes',
                                      'parent_comparisons', 'parent_mismatches',
                                      'whole_images_rebuilt')}))
