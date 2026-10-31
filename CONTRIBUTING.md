# Contributing

Thank you for looking. Cloud Locksmith is security software, so the rules here are mostly about evidence.

## Before you start

- **Bugs and ideas:** open an issue or a discussion.
- **Vulnerabilities:** report them privately instead ([SECURITY.md](SECURITY.md)).
- **Never put real tenant data in an issue,** pull request or test: no tenant IDs, user names, UPNs, tokens or screenshots of a real tenant. The quick start's fictional tenant (`src/clw/demo/fake_graph.py`) is there to reproduce things with.
- **For anything larger than a fix,** please discuss it first.

## The rules for a change

1. **Tests first, and they must fail without your change.** Security behaviour is pinned by tests, and `scripts/audit_mutation_check.py` breaks the code on purpose to prove the tests notice. If you add a security check, add a mutant that removes it.
2. **A security decision gets an entry** in [`docs/security-decisions.md`](docs/security-decisions.md): what was decided, why, the risk accepted, and the tests.
3. **Fail closed.** Unknown input, an error, or an audit write that fails means refusing, never carrying on.
4. **No interface takes a Graph URL, path, method or header from a caller.** Operations are named, and fixed in `src/clw/broker/operations.py`.
5. **No secrets** in code, tests, logs, audit records or fixtures.
6. **Claims:** documentation says only what tests demonstrate.

## Running the tests

```sh
uv sync --python 3.11
uv run pytest -m "not pg and not redis and not sandbox and not tenant and not e2e"   # unit + security
docker compose up -d postgres redis                                                 # needs .env (copy .env.example)
uv run pytest -m pg && uv run pytest -m redis                                       # database, Redis
uv run pytest -m e2e                                                                # the full stack on fake Graph (Docker)
uv run python scripts/audit_mutation_check.py                                       # every mutant must be killed
```

The `tenant` tests run only against a real test tenant you configure, and are never part of CI.

## Sign your work (DCO)

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/). Add a `Signed-off-by` line to each commit (`git commit -s`) to certify that you wrote the change, or otherwise have the right to submit it under the project's licence (Apache-2.0).
