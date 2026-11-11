import re, shutil, subprocess
from pathlib import Path
import pytest
WEB = Path(__file__).resolve().parents[1] / "web"
NAV = ["overview", "proxy", "history", "repeater", "intruder", "scanner", "sequencer", "decoder", "comparer", "websocket", "scope", "reports", "settings"]

def test_index_references_exist():
    html = (WEB / "index.html").read_text()
    refs = re.findall(r'(?:src|href)="/([^"]+)"', html)
    assert refs and all((WEB / r).exists() for r in refs), [r for r in refs if not (WEB / r).exists()]
    assert "<script>" not in html and "style=" not in html          # patuh CSP ketat

def test_every_nav_item_has_a_module():
    js = (WEB / "assets/js/app.js").read_text()
    for m in NAV:
        assert f'["{m}",' in js and (WEB / f"assets/js/modules/{m}.js").exists() and f"EX.modules.{m} =" in (WEB / f"assets/js/modules/{m}.js").read_text()

def test_no_placeholder_or_fake_markers():
    bad = re.compile(r"simulat|demo mode|ai generated|lorem ipsum|dummy|mock data|fake", re.I)
    for f in list(WEB.rglob("*.js")) + list(WEB.rglob("*.html")):
        assert not bad.search(f.read_text()), f

@pytest.mark.skipif(not shutil.which("node"), reason="node tidak tersedia")
def test_js_syntax():
    for f in WEB.rglob("*.js"):
        r = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True); assert r.returncode == 0, (f, r.stderr)

def test_static_served(client):
    assert "EXVOLT X" in client.get("/").text
    assert client.get("/assets/js/app.js").status_code == 200 and client.get("/assets/css/tokens.css").status_code == 200
    assert client.get("/assets/../main.py").status_code in (404, 200) and "uvicorn" not in client.get("/assets/../main.py").text
