# Releasing

Releases are built by `.github/workflows/release.yml` when a version tag is pushed, and are
meant to be published to PyPI by it. Nobody uploads from their own computer, and there's
no PyPI token to leak.

> **Not on PyPI yet.** The publish step failed (`invalid-publisher`: PyPI has no matching
> trusted publisher, see step 1). Until the first upload succeeds, the name
> `agent-warden` on PyPI could be claimed by **someone else**: don't `pip install` or
> `pip download` it, and don't tell users to. Install the git tag instead (needs `git`):
> `pip install "git+https://github.com/wi-abas/agent-warden@v0.4.2"`

## One-time setup (by hand, by the repository owner)

1. **PyPI trusted publisher** (missing today). The project doesn't exist on PyPI, so on
   pypi.org use *Your account > Publishing > Add a new pending publisher > GitHub* with
   exactly these values (any difference is `invalid-publisher` again):
   - PyPI project name `agent-warden`
   - Owner `wi-abas`, repository name `agent-warden`
   - Workflow name `release.yml` (the file name only)
   - Environment name `pypi`

   A pending publisher does **not** reserve the name: only the first upload does, so
   publish soon after. First check that https://pypi.org/project/agent-warden/ still
   doesn't exist. If someone else has it, stop: the package needs another name.
2. **GitHub environment.** Repository *Settings > Environments > New environment*
   `pypi`. Add yourself as a **required reviewer**, and under *Deployment branches and
   tags* allow only tags matching `v*`. A pushed tag then waits for your click.
3. **Protect tags** (optional, recommended): *Settings > Rules > Rulesets*, target tags
   `v*`, restrict creation to admins.
4. Delete any old PyPI API token for this project once trusted publishing works.

## Each release

1. Update `version` in `pyproject.toml` and move the CHANGELOG "Unreleased" section
   under the new version. Commit to `main` (through a pull request, CI green).
2. Tag and push:
   ```sh
   git tag -a v0.4.2 -m "v0.4.2"
   git push origin v0.4.2
   ```
3. The workflow checks that the tag matches the version, runs every check, builds,
   writes an SBOM, attests the files, then waits for your approval in the `pypi`
   environment before publishing. If publishing fails, the tag and the git install still
   work; fix the publisher and re-run the failed job.
4. After the first successful upload, check that the PyPI project is yours and lists this
   repository, then remove the "not on PyPI" notes here and in the README.
5. Create the GitHub release notes by hand (the workflow has no write access to the
   repository).

## Verifying a release

Only once the release is really on PyPI (not yet, see the top):

```sh
pip download agent-warden==0.4.2 --no-deps -d check/
gh attestation verify check/agent_warden-0.4.2-py3-none-any.whl --repo wi-abas/agent-warden
```

The attestation proves the file was built by this repository's release workflow from
the tagged commit. The SBOM (`sbom/agent-warden.cdx.json`) is in the workflow run's
`release-files` artifact for 90 days, and attested too.

## What this doesn't cover

- A compromised GitHub account with admin rights can still change the workflow or the
  environment rules. Use 2FA (a hardware key ideally) on GitHub and PyPI.
- The SBOM lists the locked dependencies; it doesn't mean they're free of known
  vulnerabilities (the weekly `pip-audit` job checks that).
