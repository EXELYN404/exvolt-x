from exvolt.modules import comparer as c

def test_text_diff():
    r = c.compare("a\nb\nc", "a\nB\nc\nd")
    assert r["changes"] == 2 and not r["identical"]
    assert [x["op"] for x in r["rows"]] == ["equal", "change", "equal", "insert"]

def test_ignore_options():
    assert c.compare("A  b", "a b", ignore_ws=True, ignore_case=True)["identical"]
    assert not c.compare("A", "a")["identical"]

def test_json_diff():
    r = c.compare('{"a":1,"b":[1,2],"c":"x"}', '{"a":2,"b":[1],"d":true}', mode="json")
    ops = {d["path"]: d["op"] for d in r["diffs"]}
    assert ops == {"a": "change", "b[1]": "delete", "c": "delete", "d": "insert"}

def test_bad_json_and_export(client):
    r = client.post("/api/comparer/compare", json={"left": {"text": "{"}, "right": {"text": "{}"}, "mode": "json"}, headers=client.h)
    assert r.status_code == 400
    r = client.post("/api/comparer/export", json={"left": {"text": "a"}, "right": {"text": "b"}}, headers=client.h)
    assert r.status_code == 200 and "<table>" in r.text
