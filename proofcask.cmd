@echo off
rem ProofCask Windows launcher: make the package importable while preserving the caller's CWD.
set "PROOFCASK_ROOT=%~dp0"
set "PYTHONPATH=%PROOFCASK_ROOT%;%PYTHONPATH%"
python -m proofcask %*
