import json
import pathlib
import sys

cve, raw, source, target = sys.argv[1:5]
records = json.loads(pathlib.Path(raw).read_text())
record = next(x for x in records if x['cve_id'] == cve)
snippet = record['fix_func'][0]['snippet'] if source == 'reference' else pathlib.Path(source).read_text()
item = record['vul_func'][0]
lines = pathlib.Path(target).read_text().splitlines(keepends=True)
start = int(item['start_line']) - 1
end = int(item['end_line'])
newline = '\n' if lines and lines[0].endswith('\n') else ''
replacement = snippet if snippet.endswith('\n') else snippet + newline
pathlib.Path(target).write_text(''.join(lines[:start]) + replacement + ''.join(lines[end:]))
