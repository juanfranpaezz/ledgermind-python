"""Amend round 2 (2026-09-27), security gate r2 findings.

F1: the JSON depth guard scanned RAW bytes while ``json.loads`` auto-detects UTF-16/32. U+2200 in
UTF-16LE is the bytes 00 22, which the byte scan read as a quote, hiding every later bracket: depth 65
passed the guard and depth 2000 reached json.dump / pydantic (HTTP 500). The same documents in UTF-8
were always 422.
F2: ``runner._write_json`` let RecursionError from ``json.dump`` escape (500).
Test gap: mutants M7 (child gets the full server environment) and M9 (shell=True) left the suite GREEN.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import KEY_HEADERS, REPO_ROOT
from ledgermind_api import runner
from ledgermind_api.app import create_app, json_depth_exceeds
from ledgermind_api.config import MAX_JSON_DEPTH

FORALL = "∀"  # UTF-16LE bytes 00 22: the byte 0x22 is '"'
ENCODINGS = ("utf-16-le", "utf-16", "utf-32-le")
DEPTHS = (MAX_JSON_DEPTH + 1, 2000)
TARGETS = ("snapshot-adversarial", "snapshot-recorded", "java-audit")


def _desync_document(target: str, depth: int) -> str:
    """A JSON text whose TOTAL nesting is ``depth``, with the U+2200 string placed before the deep list."""
    def deep(levels: int) -> str:
        return "[" * levels + "0" + "]" * levels

    tail = '{"a":"' + FORALL + '","b":'
    if target == "snapshot-adversarial":
        return '{"kind":"adversarial","case_label":"desync","document":' + tail + deep(depth - 2) + "}}"
    if target == "snapshot-recorded":
        return ('{"kind":"recorded","label":"clean","files":{"postings_and_hashes.json":' + tail
                + deep(depth - 3) + "}}}")
    return '{"audit":' + tail + deep(depth - 2) + "}}"


def _path(target: str) -> str:
    return "/v1/java/audit" if target == "java-audit" else "/v1/verify/snapshot"


def _true_depth(text: str) -> int:
    depth = best = 0
    for char in text.replace(FORALL, ""):  # no quote or bracket inside the strings of these documents
        if char in "[{":
            depth += 1
            best = max(best, depth)
        elif char in "]}":
            depth -= 1
    return best


def test_the_desync_documents_have_the_intended_true_depth():
    for target in TARGETS:
        for depth in DEPTHS:
            assert _true_depth(_desync_document(target, depth)) == depth


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_F1_the_depth_guard_sees_through_utf16_and_utf32(encoding):
    for target in TARGETS:
        for depth in DEPTHS:
            assert json_depth_exceeds(_desync_document(target, depth).encode(encoding), MAX_JSON_DEPTH) is True
        # does-not-fire control: the same shape AT the limit is not refused
        assert json_depth_exceeds(_desync_document(target, MAX_JSON_DEPTH).encode(encoding), MAX_JSON_DEPTH) is False


def test_F1_every_desync_body_is_422_in_every_encoding_on_every_route_and_never_5xx(settings):
    answers = []
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as client:
        for encoding in ENCODINGS:
            for target in TARGETS:
                for depth in DEPTHS:
                    response = client.post(_path(target), content=_desync_document(target, depth).encode(encoding),
                                           headers={"Content-Type": "application/json"})
                    answers.append((encoding, target, depth, response.status_code,
                                    response.headers.get("content-type", "")))
    print(answers)
    assert len(answers) == 18
    assert [a for a in answers if a[3] >= 500] == []
    assert [a for a in answers if a[3] != 422 or "problem+json" not in a[4]] == []


def test_F1_positive_control_the_same_documents_in_utf8_are_422(settings):
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as client:
        for target in TARGETS:
            response = client.post(_path(target), content=_desync_document(target, 2000).encode("utf-8"),
                                   headers={"Content-Type": "application/json"})
            assert response.status_code == 422


def test_F1_a_shallow_utf16_body_is_still_served_and_a_broken_one_is_400_never_5xx(settings):
    with TestClient(create_app(settings), headers=KEY_HEADERS, raise_server_exceptions=False) as client:
        shallow = json.dumps({"audit": {"tamperDetected": True, "chainIntact": False, "checkpointPresent": False,
                                        "verdict": FORALL}}, ensure_ascii=False)
        ok = client.post("/v1/java/audit", content=shallow.encode("utf-16-le"),
                         headers={"Content-Type": "application/json"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["java"]["status"] == "TAMPER_SUSPECTED"
        broken = client.post("/v1/java/audit", content=shallow.encode("utf-16-le") + b"\x00",
                             headers={"Content-Type": "application/json"})
        print(broken.status_code, broken.text[:200])
        assert broken.status_code == 400
        assert "problem+json" in broken.headers["content-type"]


def _nested_list(levels: int) -> list:
    value: object = 0
    for _ in range(levels):
        value = [value]
    return value  # type: ignore[return-value]


def test_F2_write_json_turns_a_recursion_error_into_a_422_problem(tmp_path):
    with pytest.raises(runner.ApiProblem) as caught:
        runner._write_json(tmp_path, "x.json", _nested_list(2000))
    assert caught.value.status == 422 and caught.value.code == "validation_error"


def test_F2_does_not_fire_a_normal_document_is_written(tmp_path):
    runner._write_json(tmp_path, "y.json", _nested_list(10))
    assert json.loads((tmp_path / "y.json").read_text(encoding="utf-8")) == _nested_list(10)


PLANTED = {"LEDGERMIND_API_KEYS_FILE": "planted-keys-path", "AWS_SECRET_ACCESS_KEY": "planted-sentinel-value",
           "HOME": "planted-home"}


def test_M7_child_env_passes_only_the_documented_variables(tmp_path):
    source = {"PATH": "p", "SYSTEMROOT": "s", "TEMP": "t1", "TMP": "t2", "TMPDIR": "t3", **PLANTED}
    env = runner.child_env(tmp_path, source)
    assert env == {"PATH": "p", "SYSTEMROOT": "s", "TEMP": "t1", "TMP": "t2", "TMPDIR": "t3",
                   "PYTHONPATH": str(tmp_path / "src")}
    only_path = runner.child_env(tmp_path, {"PATH": "p", **PLANTED})
    assert only_path == {"PATH": "p", "PYTHONPATH": str(tmp_path / "src")}


class _FakePopen:
    calls: list = []

    def __init__(self, args, **kwargs):
        _FakePopen.calls.append((args, kwargs))
        self.pid = 4242
        self.returncode = 0

    def communicate(self, timeout=None):
        return b'{"verdict": "OK"}', b""


def test_M7_M9_run_cli_passes_a_list_argv_shell_false_the_fixed_module_and_a_clean_env(monkeypatch):
    for name, value in PLANTED.items():
        monkeypatch.setenv(name, value)
    _FakePopen.calls = []
    monkeypatch.setattr(runner.subprocess, "Popen", _FakePopen)
    run = runner.run_cli("py-under-test", REPO_ROOT, ["--corpus", "recorded", "--half", "clean"], 5.0)
    assert run.exit_code == 0 and run.stdout == '{"verdict": "OK"}'
    assert len(_FakePopen.calls) == 1
    args, kwargs = _FakePopen.calls[0]
    assert isinstance(args, list) and all(isinstance(part, str) for part in args)
    assert args[:3] == ["py-under-test", "-m", "tools.verify_report"]
    assert args[-1] == "--json"
    assert kwargs.get("shell", False) is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert Path(kwargs["cwd"]) == REPO_ROOT
    assert set(kwargs["env"]) <= set(runner.PASSTHROUGH_ENV) | {"PYTHONPATH"}
    assert not set(PLANTED) & set(kwargs["env"])


def test_M10_write_json_never_overwrites_an_existing_staged_file(tmp_path):
    # Not in the gate's fix list: the gate measured mutant M10 (non-exclusive create) surviving the suite.
    (tmp_path / "x.json").write_text("original", encoding="utf-8")
    with pytest.raises(runner.ApiProblem) as caught:
        runner._write_json(tmp_path, "x.json", {"replacement": True})
    assert caught.value.status == 422
    assert (tmp_path / "x.json").read_text(encoding="utf-8") == "original"
