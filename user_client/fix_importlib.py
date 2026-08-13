import importlib.metadata as _md
import re

# Fix for Python 3.10 bug: None distribution name in entry_points
_original_normalize = _md.Prepared.normalize

def _fixed_normalize(name):
    if name is None:
        return ''
    return _original_normalize(str(name))

_md.Prepared.normalize = staticmethod(_fixed_normalize)

from gevent import monkey
# monkey.patch_all with events=False to avoid calling entry_points()
monkey.patch_all(thread=False, events=False)
