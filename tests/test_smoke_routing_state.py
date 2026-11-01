import hashlib
import hmac
import sqlite3
from pathlib import Path
import httpx
import pytest
from scripts.smoke_commerce import assert_realm

def test_acceptance_cannot_mistake_an_already_quarantined_session_for_real(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    key='synthetic-test-key';visitor='a'*32
    monkeypatch.setenv('VISITOR_SIGNING_KEY',key)
    token=visitor+'.'+hmac.new(key.encode(),visitor.encode(),hashlib.sha256).hexdigest()
    path=tmp_path/'visitors.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE visitors (id TEXT, sandbox INTEGER)')
        db.execute('INSERT INTO visitors VALUES (?,0)',(visitor,))
    with httpx.Client(cookies={'visitor_id':token}) as client:
        assert_realm(client,'real',path)
        with sqlite3.connect(path) as db:db.execute('UPDATE visitors SET sandbox=1 WHERE id=?',(visitor,))
        with pytest.raises(AssertionError,match='Expected real routing'):assert_realm(client,'real',path)
        assert_realm(client,'sandbox',path)
        with pytest.raises(ValueError):assert_realm(client,'real',tmp_path/'events.db')
