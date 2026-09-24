from __future__ import annotations

import copy
import sys
import tarfile
from pathlib import Path, PurePosixPath

COMMIT = "62378f1767f22217f7f0474260abfeeb5c2615b9"
SOURCE_ROOT = f"gpdb-archive-{COMMIT}"
SANITIZED_ROOT = f"gpdb-sanitized-{COMMIT}"
NORMALIZED_MTIME = 1_483_141_305
REMOVED_ROOTS = frozenset({"ci", "concourse"})


class ArtifactValidationError(ValueError):
    """Raised when the upstream archive does not match the expected layout."""


def normalized_relative_path(member_name: str) -> PurePosixPath:
    path = PurePosixPath(member_name)
    if path.is_absolute() or ".." in path.parts:
        raise ArtifactValidationError(f"Unsafe path in original Greenplum archive: {member_name!r}")
    if not path.parts or path.parts[0] != SOURCE_ROOT:
        raise ArtifactValidationError(
            f"Unexpected root in original Greenplum archive: {member_name!r}"
        )
    return PurePosixPath(*path.parts[1:])


def is_removed(relative_path: PurePosixPath) -> bool:
    return bool(relative_path.parts) and relative_path.parts[0] in REMOVED_ROOTS


def sanitized_member(member: tarfile.TarInfo, relative_path: PurePosixPath) -> tarfile.TarInfo:
    result = copy.copy(member)
    result.name = str(PurePosixPath(SANITIZED_ROOT, relative_path))
    result.uid = 0
    result.gid = 0
    result.uname = ""
    result.gname = ""
    result.mtime = NORMALIZED_MTIME
    result.pax_headers = {}
    if result.islnk() and result.linkname.startswith(f"{SOURCE_ROOT}/"):
        result.linkname = result.linkname.replace(SOURCE_ROOT, SANITIZED_ROOT, 1)
    return result


def validate_member_type(member: tarfile.TarInfo) -> None:
    if member.isfile() or member.isdir() or member.issym() or member.islnk():
        return
    raise ArtifactValidationError(
        f"Unsupported entry type in original Greenplum archive: {member.name!r}"
    )


def sanitize_archive(source_path: Path, destination_path: Path) -> None:
    removed_roots: set[str] = set()
    with tarfile.open(source_path, mode="r:gz") as source_archive:
        members = sorted(source_archive.getmembers(), key=lambda member: member.name)
        with tarfile.open(destination_path, mode="w", format=tarfile.GNU_FORMAT) as output_archive:
            for member in members:
                validate_member_type(member)
                relative_path = normalized_relative_path(member.name)
                if is_removed(relative_path):
                    removed_roots.add(relative_path.parts[0])
                    continue
                output_member = sanitized_member(member, relative_path)
                if member.isfile():
                    extracted_file = source_archive.extractfile(member)
                    if extracted_file is None:
                        raise ArtifactValidationError(
                            f"Unable to read file from original Greenplum archive: {member.name!r}"
                        )
                    with extracted_file:
                        output_archive.addfile(output_member, extracted_file)
                else:
                    output_archive.addfile(output_member)
    if frozenset(removed_roots) != REMOVED_ROOTS:
        missing_roots = sorted(REMOVED_ROOTS - removed_roots)
        raise ArtifactValidationError(
            f"Expected removable paths were absent from original Greenplum archive: {missing_roots}"
        )


def main(arguments: list[str]) -> int:
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError(
            f"Sanitization requires Python 3.12; found {sys.version_info.major}.{sys.version_info.minor}."
        )
    if len(arguments) != 3:
        raise ValueError("Usage: sanitize-original-greenplum.py SOURCE_ARCHIVE DESTINATION_ARCHIVE")
    source_path = Path(arguments[1]).resolve(strict=True)
    destination_path = Path(arguments[2]).resolve(strict=False)
    if source_path == destination_path:
        raise ValueError("Source and destination archives must be different files.")
    sanitize_archive(source_path, destination_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
