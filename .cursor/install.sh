#!/usr/bin/env bash
# Cloud Agent install step for Network Vitals.
#
# netquality.py is a single, pure-stdlib Python app with no third-party runtime
# dependencies, so there is nothing to "install" for the app itself. This step
# only provisions the dev/CI tooling the repo's checks rely on, mirroring
# .github/workflows/ci.yml:
#   - python3-tk : Tkinter, the app's default GUI backend (import tkinter)
#   - shellcheck : lints tools/*.sh
#   - openssl    : used by the signed-update / sign_release tests (usually preinstalled)
#   - flake8     : pyflakes (F) lint of netquality.py + tests
#
# It is idempotent: apt/pip are safe to re-run, and the trailing checks fail the
# install loudly if any required tool is missing.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends python3-tk shellcheck openssl

# Ubuntu 24.04 marks the system Python as externally managed (PEP 668); install
# the one dev-only tool into the user site with an explicit override.
python3 -m pip install --user --break-system-packages --upgrade flake8

# Verify the toolchain the checks depend on so a broken environment fails here,
# not later during lint/test.
python3 -c "import tkinter; print('tkinter', tkinter.TkVersion)"
python3 -m flake8 --version >/dev/null && echo "flake8 ready"
shellcheck --version >/dev/null && echo "shellcheck ready"
openssl version
python3 -m compileall -q netquality.py tests && echo "byte-compile OK"

echo "Network Vitals dev environment ready."
