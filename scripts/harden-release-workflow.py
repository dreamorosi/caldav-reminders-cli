#!/usr/bin/env python3
"""Re-apply security hardening to the cargo-dist generated release workflow.

`dist generate` writes .github/workflows/release.yml from dist-workspace.toml.
Three things in that template are unsafe for this repository and cannot be
configured away in cargo-dist 0.32:

1. The whole workflow is granted `contents: write`, and every job — including
   the ones that download and run a remote installer script — is handed
   `GH_TOKEN`. `github-custom-job-permissions` only reaches user-defined
   publish jobs (the template ignores it for `plan`, `host`, and friends), and
   there is no option for the root `permissions` block. Verified against
   cargo-dist 0.32.0.
2. `dist` is installed with `curl ... | sh`, with no integrity check, in the
   same step environment as that token.
3. Jobs that never touch the GitHub API still receive the token.

So this script rewrites the generated file. It is strictly a text transform
over exact expected snippets: if the upstream template changes, the matching
snippet disappears and the script fails loudly rather than silently leaving
the workflow unhardened.

Usage:
    scripts/harden-release-workflow.py            # rewrite in place
    scripts/harden-release-workflow.py --check    # fail if changes are needed

The canonical regeneration command is:
    dist generate && scripts/harden-release-workflow.py
CI runs exactly that and then `git diff --exit-code`.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

WORKFLOW = Path(".github/workflows/release.yml")

HEADER = """
# ---------------------------------------------------------------------------
# HARDENED AFTER GENERATION -- see scripts/harden-release-workflow.py
#
# This file is produced by `dist generate` and then rewritten to:
#
#   1. make the workflow token read-only by default, granting
#      `contents: write` only to the `host` job, which is the one that uploads
#      artifacts and creates the GitHub Release;
#   2. drop GH_TOKEN from every job that never calls the GitHub API, so a
#      compromised build or install step has no token to abuse;
#   3. install `dist` through scripts/install-dist.sh, which checks a pinned
#      SHA-256 digest, instead of piping a remotely fetched script into `sh`.
#
# cargo-dist 0.32 cannot express any of this: `github-custom-job-permissions`
# is only consumed for user-defined publish jobs, and neither the root
# `permissions` block nor the install command used by `plan` is configurable.
#
# Regenerate with:  dist generate && scripts/harden-release-workflow.py
# ---------------------------------------------------------------------------
""".strip("\n")

def verified_install(reason: str) -> str:
    """The replacement install step.

    Each call site gets a distinct comment so that the idempotency check in
    `apply_patches` can tell the steps apart. Sharing one string would make the
    second patch look as though it had already been applied.
    """
    return (
        f"      # Hardened: {reason}\n"
        "      - name: Install dist\n"
        "        shell: bash\n"
        "        run: ./scripts/install-dist.sh\n"
    )


@dataclass(frozen=True)
class Patch:
    """One exact-text rewrite of the generated workflow."""

    name: str
    before: str
    after: str


PATCHES: list[Patch] = [
    Patch(
        name="root permissions are read-only",
        before='name: Release\npermissions:\n  "contents": "write"\n',
        after=f"name: Release\n\n{HEADER}\npermissions:\n  contents: read\n",
    ),
    Patch(
        name="plan job cannot write",
        before='  plan:\n    runs-on: "ubuntu-22.04"\n    outputs:\n',
        after=(
            '  plan:\n    runs-on: "ubuntu-22.04"\n'
            "    # Hardened: planning only inspects the repository. It keeps a token\n"
            "    # because `dist host --steps=create` may read the GitHub API, but that\n"
            "    # token can no longer write anything.\n"
            "    permissions:\n      contents: read\n"
            "    outputs:\n"
        ),
    ),
    Patch(
        name="plan job installs a verified dist",
        before=(
            "      - name: Install dist\n"
            "        # we specify bash to get pipefail; it guards against the `curl` command\n"
            "        # failing. otherwise `sh` won't catch that `curl` returned non-0\n"
            "        shell: bash\n"
            '        run: "curl --proto \'=https\' --tlsv1.2 -LsSf '
            "https://github.com/axodotdev/cargo-dist/releases/download/v0.32.0/"
            'cargo-dist-installer.sh | sh"\n'
        ),
        after=verified_install(
            "install a digest-verified binary rather than piping the remotely "
            "fetched cargo-dist installer into a shell."
        ),
    ),
    Patch(
        name="build-local-artifacts has no token",
        before=(
            "    runs-on: ${{ matrix.runner }}\n"
            "    container: ${{ matrix.container && matrix.container.image || null }}\n"
            "    env:\n"
            "      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        ),
        after=(
            "    runs-on: ${{ matrix.runner }}\n"
            "    container: ${{ matrix.container && matrix.container.image || null }}\n"
            "    # Hardened: compiling and packaging never calls the GitHub API, so this\n"
            "    # job gets no token at all.\n"
            "    permissions:\n      contents: read\n"
            "    env:\n"
        ),
    ),
    Patch(
        name="build-local-artifacts installs a verified dist",
        before="      - name: Install dist\n        run: ${{ matrix.install_dist.run }}\n",
        after=verified_install(
            "the generated matrix command pipes a remotely fetched installer into "
            "a shell; use the digest-verified install instead."
        ),
    ),
    Patch(
        name="build-global-artifacts has no token",
        before=(
            "      - build-local-artifacts\n"
            '    runs-on: "ubuntu-22.04"\n'
            "    env:\n"
            "      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        ),
        after=(
            "      - build-local-artifacts\n"
            '    runs-on: "ubuntu-22.04"\n'
            "    # Hardened: assembling the installers never calls the GitHub API.\n"
            "    permissions:\n      contents: read\n"
            "    env:\n"
        ),
    ),
    Patch(
        name="host job is the only writer",
        before=(
            "    env:\n"
            "      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
            '    runs-on: "ubuntu-22.04"\n'
            "    outputs:\n      val: ${{ steps.host.outputs.manifest }}\n"
        ),
        after=(
            "    # Hardened: the only job permitted to write. It uploads the artifacts\n"
            "    # and creates the GitHub Release, so it needs `contents: write`.\n"
            "    permissions:\n      contents: write\n"
            "    env:\n"
            "      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
            '    runs-on: "ubuntu-22.04"\n'
            "    outputs:\n      val: ${{ steps.host.outputs.manifest }}\n"
        ),
    ),
    Patch(
        name="publish-homebrew-formula has no token for this repository",
        before=(
            "  publish-homebrew-formula:\n"
            "    needs:\n      - plan\n      - host\n"
            '    runs-on: "ubuntu-22.04"\n'
            "    env:\n"
            "      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
            "      PLAN: ${{ needs.plan.outputs.val }}\n"
        ),
        after=(
            "  publish-homebrew-formula:\n"
            "    needs:\n      - plan\n      - host\n"
            '    runs-on: "ubuntu-22.04"\n'
            "    # Hardened: the tap is a separate repository, written with\n"
            "    # HOMEBREW_TAP_TOKEN, so no rights on this repository are needed.\n"
            "    permissions:\n      contents: read\n"
            "    env:\n"
            "      PLAN: ${{ needs.plan.outputs.val }}\n"
        ),
    ),
    Patch(
        name="announce job has no token",
        before=(
            '    runs-on: "ubuntu-22.04"\n'
            "    env:\n"
            "      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
            "    steps:\n"
            "      - uses: actions/checkout@"
        ),
        after=(
            '    runs-on: "ubuntu-22.04"\n'
            "    # Hardened: nothing in this job calls the GitHub API.\n"
            "    permissions:\n      contents: read\n"
            "    steps:\n"
            "      - uses: actions/checkout@"
        ),
    ),
]

# Only these jobs may hold a token, and only `host` may write.
TOKEN_JOBS = ("plan", "host")

# `plan` and `build-local-artifacts` are the two jobs that install dist fresh;
# the rest download the cached binary from `plan`.
EXPECTED_VERIFIED_INSTALLS = 2

# The generated workflow installs rustup with a piped download, but only inside
# `if: ${{ matrix.container }}`. This project builds both targets on plain
# runners, so that step never executes; it is left in place so the file stays
# close to the template. Any *other* piped download is a failure.
ALLOWED_PIPED_DOWNLOADS = (
    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
)


def apply_patches(text: str) -> str:
    """Apply every patch, tolerating a file that is already hardened."""
    for patch in PATCHES:
        if patch.after in text:
            continue
        occurrences = text.count(patch.before)
        if occurrences != 1:
            raise SystemExit(
                f"harden-release-workflow: cannot apply {patch.name!r}: found "
                f"{occurrences} matches for the expected generated text, wanted 1.\n"
                "The cargo-dist template has probably changed. Review the new "
                "release.yml by hand, then update PATCHES in this script."
            )
        text = text.replace(patch.before, patch.after, 1)
    return text


def audit(text: str) -> list[str]:
    """Re-check the invariants the patches are meant to establish.

    Only real YAML mapping lines are counted, so the explanatory comments in
    the header cannot satisfy or trip these checks.
    """
    problems: list[str] = []

    tokens = re.findall(
        r"^\s*GH_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}$", text, re.MULTILINE
    )
    if len(tokens) != len(TOKEN_JOBS):
        problems.append(
            f"expected GH_TOKEN in exactly {len(TOKEN_JOBS)} jobs "
            f"({', '.join(TOKEN_JOBS)}), found {len(tokens)}"
        )

    writers = re.findall(r'^\s*"?contents"?: "?write"?$', text, re.MULTILINE)
    if len(writers) != 1:
        problems.append(
            f"expected exactly one `contents: write` mapping (the host job), "
            f"found {len(writers)}"
        )

    root = re.search(r"^permissions:\n\s+\"?contents\"?: \"?(\w+)\"?$", text, re.MULTILINE)
    if root is None:
        problems.append("could not find the root permissions block")
    elif root.group(1) != "read":
        problems.append(
            f"the root permissions block grants {root.group(1)!r}, wanted 'read'"
        )

    if "cargo-dist-installer.sh" in text:
        problems.append("an unverified cargo-dist installer script is still executed")

    if re.search(r"^\s*run: \$\{\{ matrix\.install_dist\.run \}\}$", text, re.MULTILINE):
        problems.append(
            "a job still installs dist with the generated matrix command, which pipes "
            "a remote script into a shell"
        )

    installs = re.findall(r"^\s*run: \./scripts/install-dist\.sh$", text, re.MULTILINE)
    if len(installs) != EXPECTED_VERIFIED_INSTALLS:
        problems.append(
            f"expected {EXPECTED_VERIFIED_INSTALLS} digest-verified dist installs "
            f"(plan and build-local-artifacts), found {len(installs)}"
        )

    for line in text.splitlines():
        stripped = line.strip()
        if "| sh" in stripped and stripped not in ALLOWED_PIPED_DOWNLOADS:
            problems.append(f"unexpected piped-to-shell download: {stripped}")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit non-zero if the workflow is not already hardened",
    )
    parser.add_argument(
        "workflow",
        nargs="?",
        default=WORKFLOW,
        type=Path,
        help=f"path to the generated workflow (default: {WORKFLOW})",
    )
    args = parser.parse_args()

    if not args.workflow.is_file():
        raise SystemExit(f"harden-release-workflow: {args.workflow} does not exist")

    original = args.workflow.read_text(encoding="utf-8")
    hardened = apply_patches(original)

    problems = audit(hardened)
    if problems:
        for problem in problems:
            print(f"harden-release-workflow: {problem}", file=sys.stderr)
        return 1

    if hardened == original:
        print(f"harden-release-workflow: {args.workflow} is already hardened")
        return 0

    if args.check:
        print(
            f"harden-release-workflow: {args.workflow} is not hardened; "
            "run scripts/harden-release-workflow.py",
            file=sys.stderr,
        )
        return 1

    args.workflow.write_text(hardened, encoding="utf-8")
    print(f"harden-release-workflow: rewrote {args.workflow}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
