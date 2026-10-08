from pathlib import Path
import sys

source, target = map(Path, sys.argv[1:3])
old = target.read_text()
replacement = source.read_text()
start = old.index("const parseUrl =")
end = old.index("\nexport default", start)
target.write_text(old[:start] + replacement + old[end:])
