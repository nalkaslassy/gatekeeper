from pathlib import Path
import re

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


def test_root_action_uses_pr_base_branch_trust_snapshot():
    combined = Path("action.yml").read_text()
    assert "GITHUB_BASE_REF" in combined
    assert "git fetch --no-tags --depth=1 origin" in combined
    assert "git show \"FETCH_HEAD:" in combined
    assert "ARGS+=(--baseline" in combined
    assert "Commit a trust snapshot to the base branch" in combined


def test_executable_workflows_pin_external_actions_to_commit_shas():
    files = [
        Path("action.yml"),
        Path(".github/workflows/ci.yml"),
        Path(".github/workflows/release.yml"),
    ]
    uses_pattern = re.compile(r"^\s*uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)
    sha_pattern = re.compile(r"^[0-9a-f]{40}$")

    found = []
    for path in files:
        for action_name, ref in uses_pattern.findall(path.read_text()):
            found.append((path, action_name, ref))
            assert sha_pattern.fullmatch(ref), (
                f"{path}: {action_name}@{ref} is not pinned to a 40-char commit SHA"
            )

    assert found


def test_action_summary_disambiguates_duplicate_package_instances():
    combined = Path("action.yml").read_text()
    assert "| Severity | Package | Locator | Rule | Why |" in combined
    assert 'event.get("locator")' in combined


def test_dependabot_tracks_actions_and_python_dev_dependencies():
    config = yaml.safe_load(Path(".github/dependabot.yml").read_text())
    updates = config["updates"]
    ecosystems = {entry["package-ecosystem"] for entry in updates}
    assert ecosystems == {"github-actions", "pip"}

    pip_entry = next(
        entry for entry in updates if entry["package-ecosystem"] == "pip"
    )
    allowed = {item["dependency-name"] for item in pip_entry["allow"]}
    assert allowed == {"pytest", "build", "ruff", "bandit"}
