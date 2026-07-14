#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


VERSION_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?$"
)

PRERELEASE_RE = re.compile(r"^(?P<prefix>\w+?)(?P<number>\d+)?$")


def bump_version(version: str, part: str) -> str:
    match = VERSION_RE.fullmatch(version)
    if not match:
        raise ValueError(f"unsupported version format: {version!r}")

    major = int(match.group("major"))
    minor = int(match.group("minor"))
    patch = int(match.group("patch"))
    prerelease = match.group("prerelease")

    if part == "major":
        major += 1
        minor = 0
        patch = 0
    elif part == "minor":
        minor += 1
        patch = 0
    elif part == "patch":
        prerelease_match = PRERELEASE_RE.fullmatch(prerelease or "")
        if prerelease_match:
            number = int(prerelease_match.group("number") or "1")
            prerelease = f"{prerelease_match.group('prefix')}{number + 1}"
        else:
            patch += 1
    else:
        raise ValueError(f"unsupported part: {part!r}")

    bumped = f"{major}.{minor}.{patch}"
    if prerelease:
        bumped = f"{bumped}-{prerelease}"
    return bumped


def update_first_version_line(lines: list[str], version: str) -> list[str]:
    updated = False
    in_package = False
    result: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
            result.append(line)
            continue

        if in_package and stripped.startswith("[") and stripped.endswith("]"):
            in_package = False

        if in_package and not updated and stripped.startswith("version = "):
            result.append(f'version = "{version}"')
            updated = True
            continue

        result.append(line)

    if not updated:
        raise RuntimeError("could not find package version line to update")

    return result


def update_lock_version(lines: list[str], package_name: str, version: str) -> list[str]:
    result: list[str] = []
    in_target_package = False
    updated = False

    for line in lines:
        stripped = line.strip()

        if stripped == "[[package]]":
            in_target_package = False
            result.append(line)
            continue

        if stripped == f'name = "{package_name}"':
            in_target_package = True
            result.append(line)
            continue

        if in_target_package and not updated and stripped.startswith("version = "):
            result.append(f'version = "{version}"')
            updated = True
            continue

        result.append(line)

    if not updated:
        raise RuntimeError(f"could not find {package_name!r} version line in Cargo.lock")

    return result


def read_package_metadata(lines: list[str]) -> tuple[str, str]:
    in_package = False
    package_name = None
    package_version = None

    for line in lines:
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
            continue

        if in_package and stripped.startswith("[") and stripped.endswith("]"):
            break

        if not in_package:
            continue

        if package_name is None and stripped.startswith('name = "'):
            package_name = stripped.split('"', 2)[1]
            continue

        if package_version is None and stripped.startswith('version = "'):
            package_version = stripped.split('"', 2)[1]
            continue

        if package_name is not None and package_version is not None:
            break

    if package_name is None:
        raise RuntimeError("could not find package name in Cargo.toml")
    if package_version is None:
        raise RuntimeError("could not find package version in Cargo.toml")

    return package_name, package_version


def ensure_no_cargo_changes(root: Path) -> None:
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "Cargo.toml", "Cargo.lock"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if status:
        raise RuntimeError("refusing to bump version while Cargo.toml or Cargo.lock has uncommitted changes")


def package_version_at_revision(root: Path, revision: str) -> str | None:
    cargo_toml = subprocess.run(
        ["git", "show", f"{revision}:Cargo.toml"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if cargo_toml.returncode != 0:
        return None

    _, version = read_package_metadata(cargo_toml.stdout.splitlines())
    return version


def ensure_head_is_not_version_bump(root: Path) -> None:
    current_version = package_version_at_revision(root, "HEAD")
    previous_version = package_version_at_revision(root, "HEAD^")

    if current_version is not None and previous_version is not None and current_version != previous_version:
        raise RuntimeError(
            "refusing to bump version because the latest commit already changed "
            f"the package version from {previous_version} to {current_version}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Bump the crate version in Cargo.toml and Cargo.lock")
    parser.add_argument("--part", choices=("major", "minor", "patch"), default="patch")
    parser.add_argument("--push", action="store_true", help="Create and push a git tag after bumping")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    cargo_toml = root / "Cargo.toml"
    cargo_lock = root / "Cargo.lock"

    ensure_no_cargo_changes(root)
    ensure_head_is_not_version_bump(root)

    cargo_toml_text = cargo_toml.read_text(encoding="utf-8")
    cargo_toml_lines = cargo_toml_text.splitlines()

    package_name, current_version = read_package_metadata(cargo_toml_lines)
    bumped_version = bump_version(current_version, args.part)

    if args.push:
        current_branch = (
            subprocess.run(
                ["git", "branch", "--show-current"],
                check=True,
                capture_output=True,
                text=True,
            )
            .stdout.strip()
        )
        if current_branch != "master":
            raise RuntimeError(f"refusing to push from branch {current_branch!r}; expected 'master'")

    cargo_toml.write_text(
        "\n".join(update_first_version_line(cargo_toml_lines, bumped_version)) + "\n",
        encoding="utf-8",
    )

    cargo_lock_lines = cargo_lock.read_text(encoding="utf-8").splitlines()
    cargo_lock.write_text("\n".join(update_lock_version(cargo_lock_lines, package_name, bumped_version)) + "\n", encoding="utf-8")

    if args.push:
        subprocess.run(["git", "add", "Cargo.toml", "Cargo.lock"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-m", f"chore(release): {bumped_version}"], cwd=root, check=True)
        subprocess.run(["git", "tag", bumped_version], cwd=root, check=True)
        subprocess.run(["git", "push", "origin", "master", "--tags"], cwd=root, check=True)

    print(bumped_version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
