$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
python (Join-Path $scriptDir "portscanner_cli.py") @args
