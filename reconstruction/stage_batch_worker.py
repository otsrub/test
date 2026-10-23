"""Bounded original-byte review and new complete leaf-source verification.

No decompiler retries. Sources and reports stay outside any Payload tree.
Whole-function results are review candidates until reconciled into the ledger.
"""
import argparse
import bisect
import hashlib
import json
import pathlib
import random
import re
import struct
import subprocess
import zipfile

ARCHIVE_SHA = 'f2a650fd7a51a7bb2bc5e8e5cc35a95236c02723ab3faeb162cca64ee62a744e'
sha = lambda b: hashlib.sha256(b).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def macho(raw):
    assert raw[:4] == bytes.fromhex('cffaedfe')
    assert struct.unpack_from('<I', raw, 4)[0] == 0x100000c
    segments, sections, symbols, starts = [], [], {}, []
    off, symtab, fs = 32, None, None
    for _ in range(struct.unpack_from('<I', raw, 16)[0]):
        cmd, size = struct.unpack_from('<II', raw, off)
        assert size >= 8 and off + size <= len(raw)
        if cmd == 0x19:
            name = raw[off+8:off+24].split(b'\0')[0].decode()
            va, vs, fo, fl = struct.unpack_from('<QQQQ', raw, off+24)
            segments.append((name, va, vs, fo, fl))
            for i in range(struct.unpack_from('<I', raw, off+64)[0]):
                p = off + 72 + i * 80
                sn = raw[p:p+16].split(b'\0')[0].decode()
                a, n, f = struct.unpack_from('<QQI', raw, p+32)
                flags = struct.unpack_from('<I', raw, p+64)[0]
                sections.append((sn, a, n, f, flags))
        elif cmd == 0x26:
            fs = struct.unpack_from('<II', raw, off+8)
        elif cmd == 2:
            symtab = struct.unpack_from('<IIII', raw, off+8)
        off += size
    if fs:
        cursor, end = fs[0], sum(fs)
        address = next(v for n, v, *_ in segments if n == '__TEXT')
        while cursor < end:
            value = shift = 0
            while True:
                b = raw[cursor]
                cursor += 1
                value |= (b & 127) << shift
                if not b & 128:
                    break
                shift += 7
                assert shift <= 63
            if not value:
                break
            address += value
            starts.append(address)
    if symtab:
        so, count, st, sz = symtab
        for i in range(count):
            p = so + i * 16
            ix, typ, sect, desc, value = struct.unpack_from('<IBBHQ', raw, p)
            if ix and ix < sz and typ & 0xe == 0xe:
                name = raw[st+ix:raw.index(b'\0', st+ix)].decode(errors='replace')
                symbols[name] = value
    return segments, sections, starts, symbols


def original_slice(raw, sections, start, end):
    for name, va, length, fo, flags in sections:
        if flags & 0x80000400 and va <= start < end <= va + length:
            return raw[fo+start-va:fo+end-va]
    raise ValueError('Boundary outside original instruction section')


def history_addresses(value, image_sha, inherited_sha=None):
    """Keep address identity scoped to its record's original image hash."""
    found = set()
    if isinstance(value, dict):
        bound = next((value[k] for k in ('image_sha256', 'original_image_sha256',
                                        'original_sha256') if k in value), inherited_sha)
        for child in value.values():
            found.update(history_addresses(child, image_sha, bound))
    elif isinstance(value, list):
        for child in value:
            found.update(history_addresses(child, image_sha, inherited_sha))
    elif isinstance(value, str) and inherited_sha == image_sha:
        found.update(int(s, 16) for s in re.findall(r'0x[0-9a-fA-F]+', value))
    return found


def previous_addresses(root, image_sha):
    found = set()
    for p in root.rglob('*.json'):
        if p.stat().st_size > 8_000_000:
            continue
        text = p.read_text(errors='replace')
        if image_sha in text:
            found.update(history_addresses(json.loads(text), image_sha))
    return found


def review(raw, row, sections, starts, dis):
    a = int(row['address'], 16)
    index = bisect.bisect_left(starts, a)
    exact = index < len(starts) and starts[index] == a
    if not exact or index + 1 == len(starts):
        return dict(row, review='compiler_boundary_unresolved', boundary_confirmed=False)
    end = starts[index + 1]
    if end - a > 65536:
        return dict(row, review='over_64KiB_review_budget', boundary_confirmed=False)
    code = original_slice(raw, sections, a, end)
    ins = list(dis.disasm(code, a))
    decoded = sum(i.size for i in ins)
    edges = []
    for i in ins:
        if i.mnemonic in ('bl', 'b', 'blr', 'br') or i.mnemonic.startswith(('b.', 'cb', 'tb')):
            edges.append({'pc': hex(i.address), 'kind': i.mnemonic, 'operands': i.op_str})
    return dict(row, review='original_bytes_reviewed; source_and_semantics_open',
                boundary_confirmed=True, end_exclusive=hex(end), original_bytes=len(code),
                original_function_sha256=sha(code), decoded_bytes=decoded,
                full_decode=decoded == len(code), control_flow=edges,
                assembly=[{'pc': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str}
                          for i in ins], whole_function_verified=False)


def leaf_source(ins):
    # Exact complete two-instruction unsigned getter, no branches/calls/globals.
    if len(ins) != 2 or ins[1].mnemonic != 'ret' or ins[1].op_str:
        return None
    op = ins[0]
    m = re.fullmatch(r'(w0|x0), \[x0(?:, #(?:0x([0-9a-f]+)|(\d+)))?\]', op.op_str)
    if not m or op.mnemonic not in ('ldrb', 'ldrh', 'ldr'):
        return None
    size = {'ldrb': 1, 'ldrh': 2}.get(op.mnemonic, 8 if m[1] == 'x0' else 4)
    if op.mnemonic in ('ldrb', 'ldrh') and m[1] != 'w0':
        return None
    offset = int(m[2], 16) if m[2] else int(m[3] or 0)
    if offset > 4096:
        return None
    source = ('typedef unsigned long long u64;\n'
              'u64 recovered(const unsigned char *p) {\n  u64 v = 0;\n' +
              ''.join(f'  v |= (u64)p[{offset+i}] << {i*8};\n' for i in range(size)) +
              '  return v;\n}\n')
    return source, offset, size


def verify_leaf(raw, address, code, source, offset, width, out, cases):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn import arm64_const as ac
    mem, stack, stop = 0x30000000, 0x40000000, 0x50000000
    regs = [getattr(ac, f'UC_ARM64_REG_X{i}') for i in range(31)]
    preserved = regs[19:30] + [getattr(ac, f'UC_ARM64_REG_D{i}') for i in range(8, 16)]
    preserved += [ac.UC_ARM64_REG_SP, ac.UC_ARM64_REG_FPCR, ac.UC_ARM64_REG_FPSR]
    out.mkdir(parents=True, exist_ok=True)
    src = out / 'recovered.c'
    src.write_text(source)
    engines, modules, diagnostics = [], [], []
    for opt in (0, 2, 3):
        obj, lib = out / f'O{opt}.o', out / f'O{opt}.dylib'
        commands = [
            ['clang-18', '-target', 'arm64-apple-ios17.0', f'-O{opt}', '-ffreestanding',
             '-fno-builtin', '-fno-stack-protector', '-Wall', '-Wextra', '-Werror',
             '-c', str(src), '-o', str(obj)],
            ['ld64.lld-18', '-arch', 'arm64', '-platform_version', 'ios', '17.0',
             '17.0', '-dylib', str(obj), '-o', str(lib)]]
        for cmd in commands:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            diagnostics.append({'argv': cmd, 'returncode': result.returncode,
                                'stdout': result.stdout, 'stderr': result.stderr})
            write(out / 'build.json', diagnostics)
            assert result.returncode == 0, result.stderr
        module = lib.read_bytes()
        segs, _, _, syms = macho(module)
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for name, va, vs, fo, fl in segs:
            if name == '__PAGEZERO' or not vs:
                continue
            lo, hi = va & ~4095, (va + vs + 4095) & ~4095
            u.mem_map(lo, hi-lo)
            if fl:
                u.mem_write(va, module[fo:fo+fl])
        engines.append((u, syms['_recovered']))
        modules.append({'optimization': opt, 'sha256': sha(module)})
    ref = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    ref.mem_map(address & ~4095, 8192)
    ref.mem_write(address, code)
    covered = set()
    ref.hook_add(UC_HOOK_CODE, lambda u, pc, size, _: covered.add(pc))
    for u, _ in [(ref, address)] + engines:
        u.mem_map(mem, 0x3000)
        u.mem_map(stack, 0x4000)
        u.mem_map(stop, 4096)
    rng, passes, failures = random.Random(address), [0, 0, 0], []
    for case in range(cases):
        data = bytearray(rng.randbytes(0x3000))
        ptr = mem + 128 + (case % 16)
        if case < 256:
            data[ptr-mem+offset:ptr-mem+offset+width] = bytes([case]) * width
        initial = [rng.getrandbits(64) for _ in preserved]
        initial[-3:] = [stack+0x2000, (case % 4) << 22, (case*0x01010101) & 0xf800009f]
        expected = None
        for index, (u, entry) in enumerate([(ref, address)] + engines):
            u.mem_write(mem, bytes(data))
            u.mem_write(stack, bytes([0xa5]) * 0x4000)
            for reg, value in zip(preserved, initial):
                u.reg_write(reg, value)
            u.reg_write(ac.UC_ARM64_REG_X0, ptr)
            u.reg_write(ac.UC_ARM64_REG_X30, stop)
            u.emu_start(entry, stop, count=256)
            actual = (u.reg_read(ac.UC_ARM64_REG_X0), bytes(u.mem_read(mem, 0x3000)),
                      tuple(u.reg_read(r) for r in preserved), u.reg_read(ac.UC_ARM64_REG_PC))
            assert actual[3] == stop
            if index == 0:
                expected = actual
            else:
                ok = actual == expected
                passes[index-1] += int(ok)
                if not ok and len(failures) < 8:
                    failures.append({'case': case, 'optimization': (0, 2, 3)[index-1],
                                     'expected_x0': expected[0], 'actual_x0': actual[0]})
    report = {'image_sha256': sha(raw), 'address': hex(address),
              'end_exclusive': hex(address+len(code)), 'original_bytes': len(code),
              'original_function_sha256': sha(code), 'source_sha256': sha(source.encode()),
              'cases': cases, 'comparisons': cases*3, 'passes': passes,
              'mismatches': cases*3-sum(passes), 'failures': failures, 'modules': modules,
              'original_instruction_locations': sorted(map(hex, covered)),
              'runtime_callees': 0, 'source_review_required': True,
              'scope': 'Complete compiler-bounded unsigned getter; finite valid-memory domain.',
              'limits': ['No all-input proof, no complete image build, no automatic accepted-ledger update.',
                         'Memory faults, races, MMIO and concurrent mutation outside tested domain.']}
    write(out / 'REPORT.json', report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', choices=['output', 'verify'], required=True)
    parser.add_argument('--shard', type=int, choices=[0, 1], required=True)
    parser.add_argument('--limit', type=int, default=64)
    parser.add_argument('--cases', type=int, default=1024)
    args = parser.parse_args()
    assert 1 <= args.limit <= 128 and 256 <= args.cases <= 4096
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    dis = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = pathlib.Path(f'stage-{args.stage}-{args.shard}')
    out.mkdir(exist_ok=True)
    archive = pathlib.Path('MobileLogic.zip')
    with archive.open('rb') as f:
        assert hashlib.file_digest(f, 'sha256').hexdigest() == ARCHIVE_SHA
    ledger = json.loads(pathlib.Path('ledger/ALL_IMAGE_RECONSTRUCTION_LEDGER.json').read_text())
    queue = [json.loads(s) for s in pathlib.Path('ledger/FLAGGED_CANDIDATE_REVIEW_QUEUE.jsonl').read_text().splitlines() if s.strip()]
    queue = {(r['image_sha256'], int(r['address'], 16)): r for r in queue}
    results, skipped, scanned = [], [], []
    # Artifact history is supplied by the workflow; never retry an already emitted key.
    history = pathlib.Path('history')
    with zipfile.ZipFile(archive) as z:
        for image in sorted(ledger['images'], key=lambda r: r['original_path']):
            digest, path = image['original_image_sha256'], image['original_path']
            if int(digest, 16) % 2 != args.shard:
                continue
            raw = z.read(path)
            assert sha(raw) == digest
            _, sections, starts, _ = macho(raw)
            starts = sorted(set(starts))
            done = previous_addresses(pathlib.Path('reconstruction'), digest)
            done |= previous_addresses(history, digest)
            scanned.append({'path': path, 'image_sha256': digest, 'compiler_starts': len(starts)})
            if args.stage == 'output':
                targets = sorted((a, r) for (s, a), r in queue.items() if s == digest)
                for address, row in targets:
                    if address in done:
                        continue
                    try:
                        result = review(raw, row, sections, starts, dis)
                    except Exception as e:
                        result = dict(row, review='review_error', error=str(e))
                    results.append(result)
                    if len(results) >= args.limit:
                        break
            else:
                for a, end in zip(starts, starts[1:]):
                    if end-a != 8 or a in done:
                        continue
                    code = original_slice(raw, sections, a, end)
                    candidate = leaf_source(list(dis.disasm(code, a)))
                    if candidate is None:
                        continue
                    source, offset, width = candidate
                    # Persist identity before compilation/emulation, including interruptions.
                    pending = {'image_sha256': digest, 'address': hex(a), 'status': 'started'}
                    write(out / digest[:12] / hex(a) / 'ATTEMPT.json', pending)
                    try:
                        result = verify_leaf(raw, a, code, source, offset, width,
                                             out / digest[:12] / hex(a), args.cases)
                    except Exception as e:
                        result = {'image_sha256': digest, 'address': hex(a),
                                  'status': 'rejected', 'error': str(e)}
                    result['original_path'] = path
                    results.append(result)
                    write(out / 'RESULTS.json', results)
                    if len(results) >= args.limit:
                        break
            if len(results) >= args.limit:
                break
    report = {'stage': args.stage, 'shard': args.shard, 'shards': 2,
              'archive_sha256': ARCHIVE_SHA, 'target_limit': args.limit,
              'selected_targets': len(results), 'scanned_images': scanned,
              'results': results, 'accepted_ledger_mutated': False,
              'decompiler_profiles_retried': 0, 'whole_images_rebuilt': 0}
    write(out / 'BATCH_REPORT.json', report)
    (out / 'ATTEMPT_KEYS.json').write_text(json.dumps([
        {'image_sha256': r['image_sha256'], 'address': r['address']} for r in results], indent=2))
    print(json.dumps({'stage': args.stage, 'shard': args.shard, 'selected': len(results),
                      'comparisons': sum(r.get('comparisons', 0) for r in results),
                      'mismatches': sum(r.get('mismatches', 0) for r in results)}))
    if args.stage == 'verify' and any(r.get('error') or r.get('mismatches') for r in results):
        raise SystemExit('Rejected candidates preserved in artifact')


if __name__ == '__main__':
    main()
