# Repository credential audit

`repo_audit.py` is a small, dependency-free security check for Git repositories. It scans only files already tracked by Git, skips binary and very large files, and reports the file, line, and rule that matched without printing the suspected secret.

## Usage

```bash
python3 repo_audit.py .
python3 repo_audit.py . --json
```

The command exits with status `0` when no patterns are found, `1` when findings are present, and `2` for an invalid repository path.

Run the tests with:

```bash
python3 -m unittest -v
```

This is a heuristic check. Treat findings as leads for review, and keep real credentials in a secret manager rather than in source files.
