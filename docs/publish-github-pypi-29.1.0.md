# ERSEC 29.1.0 — GitHub and PyPI publication

This document is the controlled publication procedure for ERSEC 29.1.0. The release workflow builds distributions once, validates them, stores the exact artifacts, and publishes those artifacts through PyPI Trusted Publishing.

## 1. GitHub repository

Create an empty GitHub repository named `ersec` under the intended owner. Do not initialize it with a second README, license, or `.gitignore` when importing this source tree.

From the ERSEC 29.1.0 source directory:

```bash
git init
git branch -M main
git add .
git commit -m "ERSEC 29.1.0"
git remote add origin https://github.com/YOUR-OWNER/ersec.git
git push -u origin main
```

Before pushing, verify that credentials, tokens, local build directories, and generated reports are not tracked.

## 2. GitHub repository settings

Enable branch protection for `main` after the first successful CI run. Require the CI checks that are actually present in the repository before merging.

For the PyPI release environment:

1. Create a GitHub Environment named `pypi`.
2. Require manual approval for this environment.
3. Do not add a PyPI API token secret when using Trusted Publishing.
4. Keep the environment restricted to the maintainers who may publish releases.

## 3. PyPI Trusted Publishing

On PyPI, register a pending Trusted Publisher for:

- PyPI project: `ersec`
- GitHub owner: `YOUR-OWNER`
- Repository: `ersec`
- Workflow: `.github/workflows/release.yml`
- Environment: `pypi`

The first publication can create the PyPI project from the pending publisher when the workflow is authorized.

## 4. TestPyPI first

Use the manual TestPyPI workflow before the production release:

```text
.github/workflows/testpypi-29.1.0.yml
```

Register the equivalent Trusted Publisher on TestPyPI using the GitHub Environment `testpypi`.

## 5. Release tag

The public release identifier is exactly `29.1.0` and the Git tag is exactly `v29.1.0`.

```bash
git tag -a v29.1.0 -m "ERSEC 29.1.0"
git push origin v29.1.0
```

The release workflow validates that the tag and `pyproject.toml` version match before building distributions.

## 6. GitHub Release

Create a GitHub Release for tag `v29.1.0`. Use the ERSEC 29.1.0 release notes and attach the generated source/archive artifacts if desired. The workflow publishes the Python distributions from the validated CI artifact rather than rebuilding during publication.

## 7. Post-release verification

After publication:

```bash
python -m pip index versions ersec
python -m pip install --upgrade ersec==29.1.0
ersec --version
ersec --self-test
```

The installed version must report `ERSEC 29.1.0` and the self-test must pass.

## 8. Never publish by API-token-in-source

Do not commit PyPI credentials, repository credentials, or target credentials. PyPI Trusted Publishing is the preferred release mechanism for GitHub-hosted projects.
