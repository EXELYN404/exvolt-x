import pytest
from exvolt.core.database import Database
from exvolt.core.scope_manager import ScopeManager, ScopeError

@pytest.fixture()
def sm(tmp_path):
    return ScopeManager(Database(tmp_path / "t.db"))

def test_empty_scope_authorizes_nothing(sm):
    ok, why = sm.check("http://example.com/")
    assert not ok and "kosong" in why

def test_include_exclude(sm):
    sm.add({"action": "include", "type": "domain", "value": "*.example.com"})
    sm.add({"action": "include", "type": "ip", "value": "10.0.0.0/24"})
    sm.add({"action": "exclude", "type": "url", "value": "https://a.example.com/admin"})
    sm.add({"action": "exclude", "type": "port", "value": "22"})
    assert sm.in_scope("https://a.example.com/x")
    assert not sm.in_scope("https://example.com/")          # wildcard tidak mencakup apex
    assert not sm.in_scope("https://a.example.com/admin/x")
    assert sm.in_scope("http://10.0.0.5/")
    assert not sm.in_scope("http://10.0.1.5/")
    assert not sm.in_scope("http://10.0.0.5:22/")
    assert not sm.in_scope("ftp://a.example.com/")
    assert not sm.in_scope("https://evilexample.com/")

def test_disabled_rule_and_validation(sm):
    r = sm.add({"action": "include", "type": "domain", "value": "x.test"})
    sm.update(r["id"], False)
    assert not sm.in_scope("http://x.test/")
    for bad in ({"action": "x", "type": "domain", "value": "a"}, {"action": "include", "type": "port", "value": "99999"},
                {"action": "include", "type": "ip", "value": "nope"}, {"action": "include", "type": "url", "value": "re:("},
                {"action": "include", "type": "domain", "value": "bad host!"}):
        with pytest.raises(ScopeError): sm.add(bad)

def test_import_export_atomic(sm):
    sm.add({"action": "include", "type": "domain", "value": "a.test"})
    data = sm.export()
    sm.clear(); assert sm.import_rules(data) == 1
    with pytest.raises(ScopeError): sm.import_rules({"format": "exvolt-scope", "rules": [data["rules"][0], {"action": "bad"}]}, replace=True)
    assert len(sm.rules()) == 1   # gagal impor tidak mengubah apa pun
    with pytest.raises(ScopeError): sm.import_rules({"format": "other"})
