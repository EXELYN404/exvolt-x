import pytest
from exvolt.modules import decoder as d

def test_roundtrips():
    for t in ("url", "base64", "base64url", "hex", "html", "unicode"):
        s = "a b&<>é/+="
        assert d.transform(t, "decode", d.transform(t, "encode", s)) == s

def test_known_values():
    assert d.transform("base64", "encode", "hi") == "aGk="
    assert d.transform("sha256", "encode", "abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert d.transform("md5", "encode", "abc") == "900150983cd24fb0d6963f7d28e17f72"
    assert d.transform("hex", "encode", "AB") == "4142"

def test_jwt_inspection_flags_none():
    out = d.transform("jwt", "decode", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.")
    assert '"alg": "none"' in out and "tidak bertanda tangan" in out and '"signature_verified": false' in out

def test_errors():
    with pytest.raises(d.DecoderError): d.transform("hex", "decode", "zz")
    with pytest.raises(d.DecoderError): d.transform("sha256", "decode", "x")
    with pytest.raises(d.DecoderError): d.transform("json", "decode", "{bad")

def test_api(client):
    r = client.post("/api/decoder/encode", json={"type": "url", "text": "a b"}, headers=client.h)
    assert r.json() == {"output": "a%20b"}
    assert client.post("/api/decoder/decode", json={"type": "hex", "text": "zz"}, headers=client.h).status_code == 400
