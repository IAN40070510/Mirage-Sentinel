from io import BytesIO
import sys
import pytest
from urllib.error import HTTPError
from scripts import wait_commerce


def test_readiness_waits_for_storefront_after_api_is_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    homes = 0
    openers = []
    class Response(BytesIO):
        status = 200
    class Opener:
        def open(self, url: str, timeout: int) -> Response:
            nonlocal homes
            calls.append(url)
            if url.endswith('/dk'):
                homes += 1
                if homes == 1:raise HTTPError(url,503,'Starting',{},None)
                return Response(b'<html>ready</html>')
            if url.endswith('/store/regions'):
                return Response(b'{"regions":[{"countries":[{"iso_2":"dk"}]}]}')
            return Response(b'{"status":"ok"}')
    monkeypatch.setattr(sys,'argv',['wait_commerce.py'])
    def build_opener(*args: object) -> Opener:
        openers.append(args)
        return Opener()
    monkeypatch.setattr(wait_commerce.urllib.request,'build_opener',build_opener)
    monkeypatch.setattr(wait_commerce.time,'sleep',lambda _:None)
    wait_commerce.main()
    assert homes == 2
    assert len(calls) == 6
    assert len(openers) == 2
    assert openers[0][0].cookiejar is not openers[1][0].cookiejar
