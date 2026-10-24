from fuzzgen4ghidra_engine.protocol import parse_command, ok, error, progress
import json

def test_parse_command():
    cmd = parse_command('{"type": "scan_targets", "params": {"binary_path": "/tmp/a.out"}}')
    assert cmd.type == "scan_targets"
    assert cmd.params["binary_path"] == "/tmp/a.out"

def test_ok_response():
    r = ok({"count": 5})
    d = json.loads(r.to_json())
    assert d["status"] == "ok"
    assert d["data"]["count"] == 5

def test_error_response():
    r = error("bad thing")
    d = json.loads(r.to_json())
    assert d["status"] == "error"
    assert d["message"] == "bad thing"

def test_progress_response():
    r = progress({"step": 3, "total": 10})
    d = json.loads(r.to_json())
    assert d["status"] == "progress"
    assert d["data"]["step"] == 3
