from pathlib import Path
import sys

source, target, name = map(Path, sys.argv[1:])
src = source.read_text()
dst = target.read_text()
start = dst.index(f'def {name}')
next_def = dst.find('\ndef ', start + 1)
if next_def < 0:
    next_def = len(dst)
target.write_text(dst[:start] + src + dst[next_def:])
