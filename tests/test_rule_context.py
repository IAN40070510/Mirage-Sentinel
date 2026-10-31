"""Literal educational/search text must not equal complete attack syntax."""
import pytest
from services.commerce.detection import RULES


@pytest.mark.parametrize('text', ['UNION SELECT SQL textbook','javascript: the definitive guide',
                                '../../ print pattern','../../../ textile illustration',
                                '紅色上衣','100% cotton','C++','size < 10'])
def test_benign_search_has_no_signature(text: str) -> None:
    assert not [name for name,rule in RULES.items() if rule.search(text)]


@pytest.mark.parametrize('label,text', [
    ('sqli',"' UNION SELECT 1--"),('sqli','UNION ALL SELECT username FROM users'),
    ('sqli',"' OR 1=1--"),('sqli','DROP TABLE customers'),('sqli','sleep(5)'),('sqli','UNION SELECT version()'),
    ('xss','javascript:alert(1)'),('xss','javascript:document.write(1)'),('xss',"javascript:location='https://example.invalid'"),('xss','javascript:(alert)(1)'),
    ('xss','<script>alert(1)</script>'),('xss','<img src=x onerror=alert(1)>'),
    ('traversal','../../etc/passwd'),('traversal','../../../windows/win.ini'),
    ('traversal','..\\..\\windows\\win.ini'),('command','; whoami')])
def test_complete_attack_syntax_still_hits(label: str,text: str) -> None:
    assert RULES[label].search(text)
