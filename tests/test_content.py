from pathlib import Path

from gatekeeper_cli.content import compare_content_snapshots, scan_content_tree


SAFE_COLORS_140 = """var colors = require('./colors');
module['exports'] = colors;
require('./extendStringPrototype')();
"""

MALICIOUS_COLORS_141 = SAFE_COLORS_140 + """
let am = require('../lib/custom/american');
am();
for (let i = 666; i < Infinity; i++) {
  if (i % 333) {
  }
  console.log('testing testing testing testing testing testing testing'.zalgo)
}
"""


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_colors_historical_content_drift_detects_new_infinite_loop(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    _write(before, "lib/index.js", SAFE_COLORS_140)
    _write(after, "lib/index.js", MALICIOUS_COLORS_141)

    diff = compare_content_snapshots(
        scan_content_tree(before),
        scan_content_tree(after),
    )

    rules = {event["rule"] for event in diff["risk_events"]}
    assert "content-infinite-loop" in rules
    event = next(e for e in diff["risk_events"] if e["rule"] == "content-infinite-loop")
    assert event["severity"] == "high"


def test_benign_version_text_change_does_not_create_capability_alert(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    _write(before, "index.js", "module.exports = { version: '1.0.0' };\n")
    _write(after, "index.js", "module.exports = { version: '1.0.1' };\n")

    diff = compare_content_snapshots(
        scan_content_tree(before),
        scan_content_tree(after),
    )
    assert diff["changed_files"] == ["index.js"]
    assert diff["risk_events"] == []


def test_new_native_binary_is_high_risk(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    (after / "addon.node").write_bytes(b"not-a-real-binary")

    diff = compare_content_snapshots(
        scan_content_tree(before),
        scan_content_tree(after),
    )
    event = next(e for e in diff["risk_events"] if e["rule"] == "content-native-binary-added")
    assert event["severity"] == "high"


def test_new_subprocess_and_environment_capabilities_are_reported(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    _write(before, "index.js", "module.exports = 1;\n")
    _write(
        after,
        "index.js",
        "const cp = require('child_process');\n"
        "console.log(process.env.HOME);\n"
        "cp.exec('echo hello');\n",
    )

    diff = compare_content_snapshots(
        scan_content_tree(before),
        scan_content_tree(after),
    )
    rules = {event["rule"] for event in diff["risk_events"]}
    assert "content-subprocess-execution" in rules
    assert "content-environment-access" in rules
