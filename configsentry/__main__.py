import sys

from .cli import main

try:
    raise SystemExit(main())
except BrokenPipeError:  # output piped to e.g. `head`
    sys.stderr.close()
    raise SystemExit(0)
