$ErrorActionPreference = "Stop"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python was not found on PATH."
    exit 1
}

Write-Host "Starting PATIENCE dashboard and trigger agent..."

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; python -m streamlit run dashboard.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; python .\agent_daemon.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; python .\trigger_worker.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; python .\api.py"

Write-Host "PATIENCE v0.5 launched."
