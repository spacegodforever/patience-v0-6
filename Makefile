PY ?= python3
.PHONY: install init run api dashboard worker mcp test eval verify-audit docker clean

install:
	$(PY) -m pip install -r requirements.txt
init:
	$(PY) patience_cli.py init --pin --agent my-agent
api:
	$(PY) api.py
dashboard:
	$(PY) -m streamlit run dashboard.py
worker:
	$(PY) worker.py
run:
	$(PY) api.py & $(PY) worker.py & $(PY) -m streamlit run dashboard.py
mcp:
	$(PY) patience_mcp.py
test:
	$(PY) -m pytest -q tests
eval:
	$(PY) tests/eval_governance.py --misses
verify-audit:
	$(PY) audit.py verify
docker:
	docker compose up --build
clean:
	find . -name __pycache__ -prune -exec rm -rf {} + ; rm -rf .pytest_cache *.lock
