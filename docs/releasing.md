# Releasing

Releases are built and published by `.github/workflows/release.yml` when a version tag
is pushed. Nobody uploads from their own computer, and there's no PyPI token to leak.

## One-time setup (by hand, by the repository owner)

1. **PyPI trusted publisher.** On pypi.org, open the `agent-warden` project (or, before
   the first upload, *Your account > Publishing > Add a pending publisher*) and add a
   GitHub publisher:
   - Owner `wi-abas`, repository `agent-warden`
   - Workflow `release.yml`
   - Environment `pypi`
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
   git tag -a v0.4.1 -m "v0.4.1"
   git push origin v0.4.1
   ```
3. The workflow checks that the tag matches the version, runs every check, builds,
   writes an SBOM, attests the files, then waits for your approval in the `pypi`
   environment before publishing.
4. Create the GitHub release notes by hand (the workflow has no write access to the
   repository).

## Verifying a release

```sh
pip download agent-warden==0.4.1 --no-deps -d check/
gh attestation verify check/agent_warden-0.4.1-py3-none-any.whl --repo wi-abas/agent-warden
```

The attestation proves the file was built by this repository's release workflow from
the tagged commit. The SBOM (`sbom/agent-warden.cdx.json`) is in the workflow run's
`release-files` artifact for 90 days, and attested too.

## What this doesn't cover

- A compromised GitHub account with admin rights can still change the workflow or the
  environment rules. Use 2FA (a hardware key ideally) on GitHub and PyPI.
- The SBOM lists the locked dependencies; it doesn't mean they're free of known
  vulnerabilities (the weekly `pip-audit` job checks that).
