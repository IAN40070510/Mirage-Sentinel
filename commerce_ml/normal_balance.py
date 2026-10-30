"""Training-only normal route groups; never used as a model feature or label."""
from __future__ import annotations

import re


def normal_route_group(text: str) -> str:
    parts = text.split('\n', 2)
    if len(parts) < 2:
        raise ValueError('Missing request method/path')
    method, path = parts[:2]
    if path.startswith('/_next/static/'):
        path = '/_next/static/*'
    elif re.fullmatch(r'/[a-z]{2}', path):
        path = '/<locale>'
    else:
        path = re.sub(r'/(?:cart|order|paycol|cus|prod|variant)_[^/]+', '/<id>', path)
    return method + ' ' + path
