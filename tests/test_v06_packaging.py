"""v0.6 step 9: packaging, `patience init`, worker, versions."""
import os, subprocess, sys
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli(tmp_path, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PATIENCE_")}
    env.update(PATIENCE_HOME=str(tmp_path), PATIENCE_APPROVERS=str(tmp_path / "approvers.yaml"),
               PATIENCE_AGENTS=str(tmp_path / "agents.yaml"), PATIENCE_AUDIT_PATH=str(tmp_path / "a.jsonl"))
    return subprocess.run([sys.executable, os.path.join(ROOT, "patience_cli.py"), *args], cwd=tmp_path,
                          env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)


def test_patience_init_creates_admin_agent_policy_env(tmp_path, monkeypatch):
    r = run_cli(tmp_path, "init", "--admin", "root", "--agent", "bot1", "--pin")
    assert r.returncode == 0, r.stderr
    envtxt = (tmp_path / ".env").read_text()
    assert "PATIENCE_LINK_SECRET=" in envtxt and oct((tmp_path / ".env").stat().st_mode)[-3:] == "600"
    assert (tmp_path / "policy.yaml").read_text() == open(os.path.join(ROOT, "policies", "default.yaml")).read()
    import re
    pw = re.search(r"password: (\S+)", r.stdout).group(1)
    pin = re.search(r"PIN for one-tap links: (\d{6})", r.stdout).group(1)
    key = re.search(r"Agent 'bot1' API key \(shown once\): (\S+)", r.stdout).group(1)
    monkeypatch.setenv("PATIENCE_APPROVERS", str(tmp_path / "approvers.yaml"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))
    import approvers, identity
    assert approvers.verify_password("root", pw)["role"] == "admin"
    assert approvers.verify_pin("root", pin)
    assert identity.resolve(key)
    assert pw not in (tmp_path / "approvers.yaml").read_text()
    # second run doesn't clobber the admin or the secret
    r2 = run_cli(tmp_path, "init", "--admin", "root")
    assert "already exists" in r2.stdout and (tmp_path / ".env").read_text() == envtxt


def test_cli_version_and_verify(tmp_path):
    assert run_cli(tmp_path, "version").stdout.strip() == "PATIENCE v0.6"
    assert run_cli(tmp_path, "verify-audit").returncode == 0


def test_worker_tick_flags_only_old_stuck(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "s.json"))
    from engine import Patience
    import worker
    p = Patience(str(tmp_path / "s.json"))
    with p.memory_store.locked():
        p.state.executions["k1"] = {"status": "executing", "claimed_at": "2020-01-01T00:00:00+00:00", "request_id": None}
        from models import now_iso
        p.state.executions["k2"] = {"status": "executing", "claimed_at": now_iso(), "request_id": None}
        p.memory_store.save(p.state)
    r = worker.tick()
    assert [f["idempotency_key"] for f in r["flagged"]] == ["k1"] and r["audit_ok"]


def test_packaging_files():
    comp = yaml.safe_load(open(os.path.join(ROOT, "docker-compose.yml")))
    assert set(comp["services"]) == {"api", "dashboard", "worker"}
    assert all(str(p).startswith("127.0.0.1:") for s in comp["services"].values() for p in s.get("ports", []))
    df = open(os.path.join(ROOT, "Dockerfile")).read()
    assert "USER patience" in df
    di = open(os.path.join(ROOT, ".dockerignore")).read()
    for s in (".env", "approvers.yaml", "agents.yaml", "patience_state.json"):
        assert s in di
    ex = open(os.path.join(ROOT, ".env.example")).read()
    assert "sk_live" not in ex and "PATIENCE_EXECUTE_LIVE=0" in ex
    assert "patience_cli:main" in open(os.path.join(ROOT, "pyproject.toml")).read()


def test_versions_are_06():
    import api, patience_mcp, patience_cli
    assert api.VERSION == patience_mcp.VERSION == patience_cli.VERSION == "0.6"
    assert "v0.6" in open(os.path.join(ROOT, "README.md")).read().splitlines()[0]
    assert "v0.6" in open(os.path.join(ROOT, "dashboard.py")).read()
