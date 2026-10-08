import json
import re
from pathlib import Path

rows = [
    ['CVE-2023-28155','bypass','bypass','blocked','COMPLETE'],
    ['CVE-2022-35949','4/4 bypass','4/4 bypass','4/4 bypass (reference mismatch)','NOT_COMPARABLE'],
    ['CVE-2025-23221','6 failures','2 failures','8/8 pass','COMPLETE'],
    ['CVE-2020-28360','50 failures','26/37 pass (11 bypasses)','37/37 pass','COMPLETE'],
    ['CVE-2023-24623','IPv6 bypass','pass','pass','COMPLETE'],
    ['CVE-2022-24825','canonicalization failures','fails PoC','pass','COMPLETE'],
    ['CVE-2024-0243','scope escape','scope escape (scheme/port)','scope checks pass','COMPLETE'],
    ['CVE-2023-5122','7 bypasses','compile failure','pass','COMPLETE'],
    ['CVE-2022-29188','bracket bypass','compile failure','pass','COMPLETE'],
    ['CVE-2022-2900','50 failures','1 regression','pass','COMPLETE'],
]
root = Path('results/experiments')
def evidence(cve):
    candidates = list(root.glob('patcheval_*'))
    norm = lambda s: re.sub(r'[^a-z0-9]', '', s.lower())
    d = next((p for p in candidates if norm(p.name) == norm('patcheval_' + cve)),
             root / ('patcheval_' + cve.lower()))
    return {m: {'path': str(d / (m + '.log')), 'exists': (d / (m + '.log')).exists(),
                'bytes': (d / (m + '.log')).stat().st_size if (d / (m + '.log')).exists() else 0}
            for m in ('baseline', 'candidate', 'reference')}
out = {'protocol':'case-specific dynamic PoCs', 'schema_version':'v04', 'rows':[
    {'cve_id':r[0],'baseline':r[1],'candidate':r[2],'reference':r[3],
     'status':r[4], 'evidence': evidence(r[0])} for r in rows
]}
Path('results/experiments/PATCHEVAL_DYNAMIC_SUMMARY_v04.json').write_text(json.dumps(out,indent=2)+'\n')
Path('results/experiments/PATCHEVAL_DYNAMIC_SUMMARY_v04.md').write_text(
    '# PatchEval Dynamic Summary v04\n\n' +
    '| CVE | Baseline | Candidate | Reference | Status |\n|---|---|---|---|---|\n' +
    ''.join(f'| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |\n' for r in rows) +
    '\n`NOT_COMPARABLE` means a required artifact, provenance, raw log, or result is missing or contradictory. The JSON includes per-mode log paths and byte counts.\n'
)
