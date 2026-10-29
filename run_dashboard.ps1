$ErrorActionPreference = "Stop"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python was not found on PATH."
    exit 1
}

python -m pip install -r requirements.txt
if (-not $env:PATIENCE_DASHBOARD_PASSWORD -and -not $env:PATIENCE_DASHBOARD_PASSWORD_SHA256) {
    Write-Host "PATIENCE_DASHBOARD_PASSWORD not set: dashboard will be READ-ONLY (no approvals)."
}
python -m streamlit run dashboard.py --server.address 127.0.0.1
