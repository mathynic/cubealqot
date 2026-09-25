"""Create an isolated, guarded benchmark build; never patch the working crate."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('directory', type=Path)
p.add_argument('--start', type=int, default=2)
p.add_argument('--end', type=int, default=20_000_000_000)
p.add_argument('--threads', type=int, default=4)
p.add_argument('--chunk-size', type=int, default=1_000_000)
p.add_argument('--timeout', type=int, default=7200)
p.add_argument('--store', type=Path, help='committed PP-04 proof store to freeze into the run')
p.add_argument('--snapshot', type=Path, help='PP-07 theorem snapshot to freeze into the run')
p.add_argument('--smoke', action='store_true')
p.add_argument('--seal', action='store_true')
p.add_argument('--verify', action='store_true')
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
dest = a.directory.resolve()
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def identities():
    files = [dest/'config.json', dest/'build/target/release/family-placement-bench.exe']
    if (dest/'theorem-snapshot.json').exists():
        files.append(dest/'theorem-snapshot.json')
    files += [f for f in (dest/'proof-store').rglob('*') if f.is_file()]
    for folder in ('src', 'scripts/m7'):
        files += [f for f in (dest/'build'/folder).rglob('*') if f.is_file() and '__pycache__' not in f.parts]
    files += [dest/'build/Cargo.toml', dest/'build/Cargo.lock']
    return {str(f.relative_to(dest)): digest(f) for f in sorted(files)}
if a.seal:
    (dest/'identities.json').write_text(json.dumps(identities(), indent=2))
elif a.verify:
    assert identities() == json.loads((dest/'identities.json').read_text()), 'Benchmark inputs or binary changed; use a new run directory'
else:
    assert 2 <= a.start <= a.end and a.threads > 0 and a.chunk_size > 0
    if not a.smoke:
        assert a.store is not None and a.snapshot is not None, \
            '--store and --snapshot are required for a non-smoke benchmark'
        assert a.store.is_dir(), f'proof store is not a directory: {a.store}'
        assert a.snapshot.is_file(), f'theorem snapshot is not a file: {a.snapshot}'
        snapshot = json.loads(a.snapshot.read_text())
        required = {'schema_version', 'snapshot_id', 'store_id', 'policy_id', 'rhs_version', 'admissions'}
        assert required.issubset(snapshot), 'theorem snapshot is missing required identity fields'
    dest.mkdir(parents=True, exist_ok=False)
    build = dest/'build'
    build.mkdir()
    for folder in ('src', 'benches', 'tests', 'scripts/m7'):
        shutil.copytree(root/folder, build/folder, ignore=shutil.ignore_patterns('__pycache__'))
    for file in ('Cargo.toml', 'Cargo.lock'):
        shutil.copy2(root/file, build/file)
    source_hashes = {str(f.relative_to(root)):digest(f) for f in (root/'src').rglob('*.rs')}
    (dest/'original-source-hashes.json').write_text(json.dumps(source_hashes, indent=2))
    f = build/'src/filters/mod.rs'
    s = f.read_text()
    start = s.index('pub fn run_canonical_with_family_map(')
    b = s.index('    evaluated.push(Stage::F2);', start)
    e = s.index('    let family_witness =', b)
    block = s[b:e]
    assert 'family_witness: None' in block and 'Outcome::rejected_f2' in block
    end = s.index('    evaluated.push(Stage::F3);', e)
    family = s[e:end]
    assert 'lookup_family_map(map, candidate)' in family
    s = s[:b] + '    let before = BENCHMARK_BEFORE_F2.load(std::sync::atomic::Ordering::Relaxed);\n    if !before {\n' + block + '    }\n' + family + '    if before {\n' + block + '    }\n' + s[end:]
    s += '''
// Benchmark-only switch. Change only after all worker threads have joined.
pub static BENCHMARK_BEFORE_F2: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn benchmark_family_stages() -> [Stage;9] {
    let mut stages = FAMILY_STAGES;
    if BENCHMARK_BEFORE_F2.load(std::sync::atomic::Ordering::Relaxed) { stages.swap(1,2); }
    stages
}
'''
    f.write_text(s)
    # Statistics and run-premise metadata must follow the experimental order.
    for name in ('stats.rs', 'survivors.rs'):
        f = build/'src'/name
        s = f.read_text().replace('filters::FAMILY_STAGES', 'filters::benchmark_family_stages()')
        f.write_text(s)
    # Only F8 records are requested; both swapped stages remain before F8.
    shutil.copy2(root/'scripts/m7/placement-benchmark.rs', build/'src/bin/family-placement-bench.rs')
    (dest/'proof-store').mkdir()
    if not a.smoke:
        shutil.copytree(a.store, dest/'proof-store', dirs_exist_ok=True)
        shutil.copy2(a.snapshot, dest/'theorem-snapshot.json')
    config = dict(start=a.start, end=a.end, threads=a.threads, chunk_size=a.chunk_size,
                  timeout_seconds=a.timeout, local_smoke=a.smoke,
                  benchmark_contract_version=2,
                  admission_mode='self-contained-local-smoke' if a.smoke else 'offline-loaded-committed-store',
                  snapshot_file=None if a.smoke else 'theorem-snapshot.json',
                  store_directory=None if a.smoke else 'proof-store',
                  interpretation='paired native range benchmark; offline committed admission load and report I/O excluded; inclusive endpoints')
    (dest/'config.json').write_text(json.dumps(config, indent=2))
    print(dest)
