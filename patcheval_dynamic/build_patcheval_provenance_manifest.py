import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / 'results/experiments/PATCHEVAL_DYNAMIC_SUMMARY_v04.json'

def norm(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())

summary = json.loads(SUMMARY.read_text())
exp = ROOT / 'results/experiments'
rows = []
for row in summary['rows']:
    cve = row['cve_id']
    d = next((p for p in exp.glob('patcheval_*') if norm(p.name) == norm('patcheval_' + cve)), None)
    modes = {}
    for mode in ('baseline', 'candidate', 'reference'):
        p = d / (mode + '.log') if d else exp / ('patcheval_' + cve) / (mode + '.log')
        text = p.read_text(errors='replace') if p.exists() else ''
        exits = [int(x) for x in re.findall(r'(?:ssrf|security|project|candidate|baseline)[^\n]*exit[=:](\d+)', text, re.I)]
        modes[mode] = {
            'log': str(p.relative_to(ROOT)),
            'bytes': p.stat().st_size if p.exists() else 0,
            'exit_tokens': exits,
            'exit_code_recorded': bool(exits),
            'raw_log_available': p.exists() and p.stat().st_size > 0,
        }
    rows.append({'cve_id': cve, 'image': 'ghcr.io/patcheval-cve/patcheval-cve:' + cve.lower(), 'status': row['status'], 'reported': row, 'modes': modes})

out = {'schema': 'patcheval-provenance-v01', 'protocol': 'case-specific PoC; project regression status kept separate', 'rows': rows}
path = ROOT / 'results/experiments/PATCHEVAL_PROVENANCE_v01.json'
path.write_text(json.dumps(out, indent=2) + '\n')
print(path)
