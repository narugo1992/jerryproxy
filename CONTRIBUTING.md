# Contributing to JerryProxy

JerryProxy is pre-alpha. Start by reading [CLAUDE.md](CLAUDE.md), the WIP
boundary in [README.md](README.md), and the open implementation-plan issue.

## Development setup

```shell
python -m pip install -e .
python -m pip install -r requirements-test.txt
python -m pip install -r requirements-dev.txt
python -m pip install -r requirements-doc.txt
make check
```

## Contribution requirements

- Preserve Python 3.7 source compatibility.
- Keep backend binaries external to the Python package.
- Add deterministic tests for behavior and adversarial tests for security
  boundaries.
- Do not put real subscription URLs, UUIDs, hosts, passwords, controller
  secrets, or backend logs in issues, commits, fixtures, or snapshots.
- Keep README/docs WIP claims aligned with actual behavior.
- Preserve accurate Git authorship. `narugo1992` owns releases and protected
  backend-catalog changes; other contributors participate through normal
  commits and pull requests.

## Verification

```shell
make unittest
make lint
make docs
make package
jerryproxy --home ./test_self_check self-check
```

Use `make unittest RANGE_DIR=./backend` for a focused backend-manager pass.
