from pathlib import Path

import yaml


def test_root_action_is_focused_on_trust_review():
    path = Path("action.yml")
    assert path.exists()
    action = yaml.safe_load(path.read_text())

    assert action["runs"]["using"] == "composite"
    assert "online-content" in action["inputs"]
    steps = action["runs"]["steps"]
    combined = "\n".join(str(step) for step in steps)
    assert "gatekeeper-trust-drift" in combined
    assert 'bin/gatekeeper" review' in combined
    assert "gatekeeper scan" not in combined
    assert not Path("action/action.yml").exists()
