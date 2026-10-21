#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results
python -m pytest tests/ -v --junitxml=results/junit.xml 2>&1 | tee results/validation.log
python --version > results/python_version.txt
python -m pip freeze > results/requirements-lock.txt
PYTHONPATH=. python scripts/conformance_probe.py | tee results/conformance_probe.json
sha256sum config.py encoding.py kdf.py puf.py sampling.py protocol.py stage4_security.py > results/source_sha256.txt
printf '\nValidation evidence saved in results/.\n'
