"""MW-00 read-only inventory and installed-API probe, not a proof backend.

Run with host Python from any directory. Reuses out/m7-mw-qualification/mw00.
The internal --sage-probe entry runs this same file in the pinned environment.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

from local_config import get_local_setting

ROOT = Path(__file__).resolve().parents[2]
PREVIOUS_36 = {2,3,4,5,7,8,9,11,13,14,15,17,19,20,21,25,33,35,37,41,43,47,
               49,52,53,55,57,59,63,77,85,97,103,111,129,140}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def manifest(root):
    return {p.relative_to(root).as_posix(): {'sha256': digest(p), 'bytes': p.stat().st_size}
            for p in sorted(Path(root).rglob('*')) if p.is_file()}


def reconcile(previous, admitted, records):
    certified = [int(r['n']) for r in records
                 if r['result']['status'] in ('CERTIFIED_EMPTY', 'CERTIFIED_SOLUTIONS')]
    return {'previous_admissions': sorted(previous), 'current_admissions': sorted(admitted),
            'new_admissions': sorted(admitted - previous),
            'certified_result_rows': len(certified), 'certified_distinct_n': sorted(set(certified)),
            'certified_without_current_admission': sorted(set(certified) - admitted)}


def save(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    tmp.replace(path)


def sage_probe():
    import inspect
    import platform
    import importlib.util
    from sage.all import EllipticCurve, GF, QQ, ZZ, pari, proof, alarm, cancel_alarm
    from sage.version import version
    from sage.libs.eclib.interface import mwrank_MordellWeil
    proof.all(True)
    alarm(180)
    try:
        report = {'sage': version, 'python': platform.python_version(), 'pari': str(pari.version())}
        prefix = Path(sys.prefix)
        report['packages'] = [json.loads(p.read_text()) for p in sorted((prefix / 'conda-meta').glob('*.json'))
                              if p.name.startswith(('eclib-', 'pari-', 'sage-', 'python-'))]
        modules = ['sage.libs.eclib.interface', 'sage.libs.eclib.mwrank',
                   'sage.schemes.elliptic_curves.ell_rational_field', 'cypari2.gen']
        report['module_identities'] = {}
        for name in modules:
            path = Path(importlib.util.find_spec(name).origin)
            report['module_identities'][name] = {'path': str(path), 'sha256': digest(path)}
        report['eclib_library_identities'] = {str(p): digest(p) for p in sorted((prefix/'lib').glob('libec.so*')) if p.is_file()}
        report['installed_contracts'] = {name: inspect.getsource(getattr(mwrank_MordellWeil, name))
                                          for name in ('process', 'rank', 'points', 'saturate')}
        report['pari_contracts'] = {name: str(getattr(pari, name).__doc__)
                                    for name in ('ellrank', 'ell2cover', 'ellheegner', 'hyperellratpoints')}
        E = EllipticCurve([0,1464,0,1464*133,1464*133**2])
        P = E(QQ(-8330)/9, QQ(473032)/27)
        Em = E.minimal_model()
        phi = E.isomorphism_to(Em)
        psi = ~phi
        assert psi(phi(P)) == P
        # Explicit scale-2 nonminimal model exercises nontrivial u, not just translation.
        B = EllipticCurve([0,0,1,-7,6]); G = B(0,2)
        C = EllipticCurve([0,0,8,-112,384]); H = C(0,16)
        f = C.isomorphism_to(B); g = ~f
        assert g(f(H)) == H and f(g(G)) == G
        assert abs(f.u) == 2
        report['maps'] = [{'original': list(map(str, E.ainvs())), 'minimal': list(map(str, Em.ainvs())),
                           'forward': str(phi), 'inverse': str(psi), 'round_trip': True},
                          {'original': list(map(str, C.ainvs())), 'minimal': list(map(str, B.ainvs())),
                           'forward': str(f), 'inverse': str(g), 'round_trip': True}]
        pari.set_real_precision_bits(128); pari.setrand(1)
        rank = E.pari_curve().ellrank(0, points=[[P[0], P[1]]], precision=128)
        assert int(rank[0]) == int(rank[1]) == 1
        report['rank'] = {'raw': str(rank), 'bounds': [int(rank[0]), int(rank[1])],
                          'hypothesis': 'algebraic PARI bound; not analytic rank'}
        S = phi(2*P); z = S[0].denominator().lcm(S[1].denominator())
        triple = [ZZ(z*S[0]), ZZ(z*S[1]), ZZ(z)]
        mw = mwrank_MordellWeil(Em.mwrank_curve(), False)
        mw.process([triple], saturation_bound=0)
        processed = mw.points()
        assert mw.rank() == 1
        ok, index, unresolved = mw.saturate(max_prime=-1, min_prime=2)
        # Qualify the actual production unresolved-prime parser as well.
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location('mw00_helper', ROOT / 'scripts/m7/sage_integral_points.py')
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        parsed_index, parsed_unresolved = helper.validate_saturation_result((ok,index,unresolved))
        assert parsed_index == 2 and parsed_unresolved == ()
        outputs = [Em([QQ(a)/c, QQ(b)/c]) for a,b,c in mw.points()]
        assert len(outputs) == 1 and 2*psi(outputs[0]) in (2*P, -2*P)
        report['saturation'] = {'input_triple': list(map(str,triple)), 'processed': str(processed),
                                'max_prime': -1, 'min_prime': 2, 'ok': bool(ok), 'index': int(index),
                                'unresolved_raw': str(unresolved), 'output_triples': str(mw.points()),
                                'returned_basis_verified': True,
                                'trust': 'pinned eclib all-prime bound; not an independent formal proof'}
        T = EllipticCurve([-25,4]); covers = T.pari_curve().ell2cover()
        found = None
        for cover in covers:
            quartic, mapping = cover[0], cover[1]
            for point in pari.hyperellratpoints(quartic, 10):
                mapped = pari.substvec(mapping, ['x','y'], point)
                R = T([QQ(mapped[0]), QQ(mapped[1])])
                found = {'quartic': str(quartic), 'map': str(mapping), 'point': str(point),
                         'mapped_point': str(R), 'exact_membership': True}
                break
            if found: break
        assert found is not None
        report['cover_map'] = found
        hpcurve = EllipticCurve([-157**2,0])
        hp = hpcurve.pari_curve().ellheegner()
        HP = hpcurve([QQ(hp[0]), QQ(hp[1])])
        assert not HP.is_zero() and HP.order() == float('inf')
        report['heegner'] = {'model': list(map(str,hpcurve.ainvs())), 'point': str(HP),
                             'exact_membership': True, 'role': 'candidate production only; analytic rank-one hypothesis'}
        # Small exact finite-arithmetic contract fixture, not MW-02 production code.
        E19 = EllipticCurve([0,7240,0,7240*381,7240*381**2])
        witnesses = [(2,17,25,1,[(19,[(1,0),(0,1)]),(23,[(1,1)])]),
                     (3,31,28,2,[(11,[(1,0),(1,1),(0,1)]),(41,[(1,2)])])]
        for ell,p0,order,mult,checks in witnesses:
            assert E19.discriminant()%p0 != 0 and p0 != ell
            assert E19.change_ring(GF(p0)).cardinality() == order
            assert order%ell != 0
            remaining = {(1,b) for b in range(ell)} | {(0,1)}
            for p,directions in checks:
                assert E19.discriminant()%p != 0 and p != ell
                F = E19.change_ring(GF(p)); group = F.points()
                # Independent equation-count implementation for a1=a3=0 fixture.
                direct = 1+sum((y*y-x**3-7240*x*x-7240*381*x-7240*381**2)%p == 0
                               for x in range(p) for y in range(p))
                assert len(group) == direct
                multiples = {ell*R for R in group}
                P19 = mult*F(-3666,197412); Q19 = mult*F(-46,30648)
                for a,b in directions:
                    assert a*P19+b*Q19 not in multiples
                    remaining.remove((a,b))
            assert not remaining
        report['finite_field_witness_fixtures'] = {'verified': True, 'cases': witnesses,
            'scope':'MW-00 exact finite group arithmetic; broader MW-02 adversarial tests still required'}
        report['success'] = True
        return report
    finally:
        cancel_alarm()


def record():
    out = ROOT / 'out/m7-mw-qualification/mw00'
    out.mkdir(parents=True, exist_ok=True)
    (out/'sage-api.json').unlink(missing_ok=True)  # No stale successful probe after a failed recapture.
    store = ROOT / 'out/m7-proof-store'
    binary = ROOT / 'target/release/cubealqot-family.exe'
    before = manifest(store)
    save(out / 'store-before.json', before)
    env = dict(os.environ, PATH='')
    offline = {}
    for verb in ('list', 'check'):
        result = subprocess.run([str(binary),'store',verb,'--store',str(store)],
                                env=env, capture_output=True, text=True, timeout=180, check=True)
        value = json.loads(result.stdout)
        assert value['backend_invoked'] is False
        offline[verb] = value
    admitted = {int(e['n']) for e in offline['list']['entries']}
    records = []; runs = []
    for path in sorted((ROOT/'out').glob('**/runs/*/results.jsonl')):
        data = [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
        if not all('n' in r and 'result' in r for r in data): continue
        records.extend(data)
        manifest_path = path.with_name('manifest.json')
        runs.append({'path': str(path.relative_to(ROOT)), 'sha256': digest(path), 'rows': data,
                     'manifest': json.loads(manifest_path.read_text(encoding='utf-8-sig')) if manifest_path.exists() else None,
                     'manifest_sha256': digest(manifest_path) if manifest_path.exists() else None})
    classifications = {}
    for path in sorted((ROOT/'out').glob('**/m7-adapter-evidence/*/request.json')):
        request = json.loads(path.read_text(encoding='utf-8-sig'))
        n = int(request['problem']['n'])
        if n in admitted: continue
        log = path.with_name('backend.log')
        if not log.exists(): continue
        events = []
        for line in log.read_text(errors='replace').splitlines():
            try: event = json.loads(line)
            except ValueError: continue
            if isinstance(event,dict) and event.get('classification'): events.append(event)
        stamp = path.stat().st_mtime_ns
        if str(n) not in classifications or stamp > classifications[str(n)]['mtime_ns']:
            classifications[str(n)] = {'mtime_ns': stamp, 'request': str(path.relative_to(ROOT)),
                'request_sha256': digest(path), 'backend_log': str(log.relative_to(ROOT)),
                'backend_log_sha256': digest(log), 'problem': request['problem'],
                'helper_sha256': request['policy']['script_sha256'], 'last_classification': events[-1] if events else None}
    source_paths = ['src/family/sage.rs','src/family/admission.rs','src/family/persistence.rs',
                    'src/family/migration.rs','src/bin/cubealqot-family.rs',
                    'scripts/m7/sage_integral_points.py','scripts/m7/sage_contract_smoke.py',
                    'scripts/m7/run-candidate-campaign.ps1','scripts/m7/record_mw00_baseline.py',
                    'tests/m7_mw00.py','Cargo.lock']
    sources = {s: digest(ROOT/s) for s in source_paths}
    wsl = ['wsl.exe','--distribution','Ubuntu-26.04','--exec']
    script = subprocess.check_output(wsl+['wslpath','-a','-u',str(Path(__file__).resolve())],text=True).strip()
    conda = get_local_setting('CUBEALQOT_CONDA_EXECUTABLE', 'conda')
    result = subprocess.run(wsl+[conda,'run','--no-capture-output',
                                '--name','cubealqot-m7','python',script,'--sage-probe'],
                            capture_output=True, text=True, timeout=240)
    (out/'sage-probe.stdout.txt').write_text(result.stdout,encoding='utf-8')
    (out/'sage-probe.stderr.txt').write_text(result.stderr,encoding='utf-8')
    after = manifest(store); save(out/'store-after.json',after)
    save(out/'baseline.json', {'task':'MW-00','captured_utc':datetime.now(timezone.utc).isoformat(),
         'binary_sha256':digest(binary),'sources':sources,'offline':offline,'offline_path':'',
         'accounting':reconcile(PREVIOUS_36,admitted,records),'runs':runs,
         'unadmitted_latest_evidence':classifications,'store_unchanged':before==after,
         'probe_exit_code':result.returncode})
    assert before == after, 'Proof-store bytes changed during capture; investigate concurrent writers.'
    if result.returncode: raise RuntimeError('Sage probe failed; inspect retained stderr; no qualification success.')
    probe = json.loads(result.stdout)
    assert probe['success'] is True
    save(out/'sage-api.json',probe)
    print(json.dumps({'admissions':len(admitted),'new_since_36':sorted(admitted-PREVIOUS_36),
                      'store_unchanged':True,'sage_probe':'passed','output':str(out)},indent=2))


if __name__ == '__main__':
    if sys.argv[1:] == ['--sage-probe']:
        print(json.dumps(sage_probe(), indent=2))
    elif not sys.argv[1:]:
        record()
    else:
        raise SystemExit('Usage: python scripts/m7/record_mw00_baseline.py')
