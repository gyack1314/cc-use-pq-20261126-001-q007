"""从外馆仍持有的文件中制备可核对的修复交割材料。

外馆只需要保存过的档案引用和当时取出的文件。请求列出每个目标对象及其在可信清单
中的文件、分片序号、偏移和长度；外馆按这些位置取出字节，逐片核对摘要后连同出处
一起装入交割。制备过程不访问库房，也不重新发布任何退役版本的字节。
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
from tempfile import mkdtemp

from strata.runtime.errors import invalid
from strata.runtime.jsonwire import read_json
from strata.runtime.media import BLOCK_SIZE, Media, sync_directory
from strata.transfer.manifest import (
    MAX_PART, archive_path, canonical, collection_id, digest_bytes, integer,
    reference_id, sha256,
)

FORMAT = "strata-repair-handoff-v1"
DESCRIPTOR = "handoff.json"
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
MAX_DESCRIPTOR = 2 * 1024 * 1024
MAX_TARGETS = 100
MAX_REFERENCES = 64
CITATION_FIELDS = {"collection", "revision", "manifest_sha256", "path", "part_index"}
REFERENCE_FIELDS = {"collection", "revision", "manifest_sha256", "path", "part_index",
                    "part_offset", "part_size", "file_sha256", "file_size", "retired"}


@dataclass(frozen=True)
class Offer:
    digest: str
    size: int
    citation: dict

    def as_dict(self) -> dict:
        return {"digest": self.digest, "size": self.size, "citation": dict(self.citation)}


@dataclass(frozen=True)
class Handoff:
    root: Path
    request: str
    token: str
    targets: int
    offers: tuple[Offer, ...]
    unavailable: tuple[str, ...]
    unusable: tuple[dict, ...]

    def descriptor(self) -> dict:
        return {
            "format": FORMAT, "request": self.request, "token": self.token,
            "targets": self.targets, "offers": [offer.as_dict() for offer in self.offers],
            "unavailable": list(self.unavailable), "unusable": list(self.unusable),
        }

    def materials(self) -> list[dict]:
        return [offer.as_dict() for offer in self.offers]

    def media(self) -> Media:
        root = self.root / "parts"
        if not root.is_dir() or root.is_symlink():
            raise invalid("Repair handoff is missing its parts directory")
        return Media(root)


def handoff_token(request: str, offers: list[dict]) -> str:
    """同一份材料重复提交使用同一个令牌，库房凭它看回已结算的批次。"""
    body = canonical({"request": request, "materials": offers})
    return "handoff-" + digest_bytes(body.encode("utf-8"))[:32]


@dataclass(frozen=True)
class Reference:
    collection: str
    revision: int
    manifest_sha256: str
    path: str
    part_index: int
    part_offset: int
    part_size: int
    file_sha256: str
    file_size: int
    retired: bool

    @property
    def path_identity(self) -> tuple[int, str]:
        return (self.file_size, self.file_sha256)

    def citation(self) -> dict:
        return {
            "collection": self.collection, "revision": self.revision,
            "manifest_sha256": self.manifest_sha256, "path": self.path,
            "part_index": self.part_index,
        }


@dataclass(frozen=True)
class Target:
    digest: str
    size: int
    references: tuple[Reference, ...]


def _read_request(path: Path) -> tuple[str, list[Target]]:
    try:
        if path.is_symlink():
            raise invalid("Repair request must be a regular file")
        with path.open("rb") as source:
            raw = source.read(MAX_DESCRIPTOR + 1)
    except OSError as error:
        raise invalid("Cannot read the repair request", detail=str(error)) from error
    if len(raw) > MAX_DESCRIPTOR:
        raise invalid("Repair request exceeds the byte limit")
    try:
        value = read_json(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise invalid("Repair request is not unambiguous JSON") from None
    if not isinstance(value, dict):
        raise invalid("Repair request must be an object")
    request = value.get("id")
    if not isinstance(request, str) or not REQUEST_ID.fullmatch(request):
        raise invalid("Repair request has an invalid identity")
    raw_targets = value.get("targets")
    if not isinstance(raw_targets, list) or not 1 <= len(raw_targets) <= MAX_TARGETS:
        raise invalid("Repair request has an invalid target list")
    targets = []
    seen = set()
    for item in raw_targets:
        if not isinstance(item, dict):
            raise invalid("Repair request target must be an object")
        digest = sha256(item.get("digest"))
        size = integer(item.get("size"), 1, MAX_PART, "target size")
        if digest in seen:
            raise invalid("Repair request repeats a target", digest=digest)
        seen.add(digest)
        raw_references = item.get("references")
        if not isinstance(raw_references, list) or len(raw_references) > MAX_REFERENCES:
            raise invalid("Repair target has an invalid reference list", digest=digest)
        references = []
        for raw_reference in raw_references:
            if not isinstance(raw_reference, dict):
                raise invalid("Repair reference must be an object", digest=digest)
            missing_fields = REFERENCE_FIELDS - set(raw_reference)
            if missing_fields:
                raise invalid("Repair reference is missing fields", digest=digest,
                              missing=sorted(missing_fields))
            collection = collection_id(raw_reference["collection"])
            revision = integer(raw_reference["revision"], 1, 2**63 - 1, "reference revision")
            manifest_sha256 = sha256(raw_reference["manifest_sha256"])
            path = archive_path(raw_reference["path"])
            part_index = integer(raw_reference["part_index"], 0, 8191, "reference part index")
            part_offset = integer(raw_reference["part_offset"], 0, 4 * 1024 * 1024 * 1024,
                                  "reference part offset")
            part_size = integer(raw_reference["part_size"], 1, MAX_PART, "reference part size")
            file_sha256 = sha256(raw_reference["file_sha256"])
            file_size = integer(raw_reference["file_size"], 0, 4 * 1024 * 1024 * 1024,
                                "reference file size")
            retired = raw_reference["retired"]
            if type(retired) is not bool:
                raise invalid("Repair reference retirement must be a boolean", digest=digest)
            if part_offset + part_size > file_size:
                raise invalid("Repair reference part lies outside its file", digest=digest)
            references.append(Reference(collection, revision, manifest_sha256, path, part_index,
                                        part_offset, part_size, file_sha256, file_size, retired))
        references.sort(key=lambda reference: reference.retired)
        targets.append(Target(digest, size, tuple(references)))
    return request, targets


def _identity(path: Path) -> tuple[int, str] | None:
    """完整读取仍持有的普通文件，返回打开时的长度与摘要；不可读时返回 None。"""
    try:
        with path.open("rb") as source:
            record = os.fstat(source.fileno())
            if not stat.S_ISREG(record.st_mode):
                return None
            hasher = hashlib.sha256()
            while block := source.read(BLOCK_SIZE):
                hasher.update(block)
            return record.st_size, hasher.hexdigest()
    except OSError:
        return None


def _held_files(held: Path) -> list[Path]:
    result = []

    def scan_error(error):
        raise invalid("Could not read held materials", detail=str(error))

    for root, dirs, names in os.walk(held, followlinks=False, onerror=scan_error):
        base = Path(root)
        for name in sorted(names):
            path = base / name
            try:
                if stat.S_ISREG(path.lstat().st_mode):
                    result.append(path)
            except OSError:
                continue
    return sorted(result, key=lambda path: path.relative_to(held).as_posix())


def _extract(held_file: Path, reference: Reference, digest: str, media: Media,
             stored: set[str]) -> None:
    """按引用给出的文件位置读出单个分片，并核对长度与摘要。"""
    from io import BytesIO

    try:
        with held_file.open("rb") as source:
            source.seek(reference.part_offset)
            block = source.read(reference.part_size)
    except OSError as error:
        raise invalid("Could not read held fragment", path=str(held_file)) from error
    if len(block) != reference.part_size or hashlib.sha256(block).hexdigest() != digest:
        raise invalid("Held fragment does not match the archival reference", digest=digest)
    if digest not in stored:
        media.install(digest, reference.part_size, BytesIO(block))
        stored.add(digest)


def prepare_salvage(held: Path, destination: Path, *, request_path: Path,
                    token: str | None = None) -> Handoff:
    """用外馆仍持有的文件和保存过的请求制备交割材料。"""
    request, targets = _read_request(request_path)
    if not held.is_dir() or held.is_symlink():
        raise invalid("Held materials must be a local directory")
    held = held.resolve()
    if os.path.lexists(destination):
        raise invalid("Handoff destination already exists", path=str(destination))
    destination = destination.resolve()
    if destination.is_relative_to(held):
        raise invalid("Handoff destination must be outside the held directory")
    if not destination.parent.is_dir():
        raise invalid("Handoff destination parent does not exist")

    scratch = Path(mkdtemp(prefix=".handoff-", dir=destination.parent))
    try:
        media = Media(scratch / "parts")

        # 只有与可信清单记录的长度和摘要一致的文件才可用于核对；同名但内容不同的文件单独列出。
        acceptable: dict[tuple[int, str], list[str]] = {}
        for target in targets:
            for reference in target.references:
                accepted = acceptable.setdefault(reference.path_identity, [])
                if reference.path not in accepted:
                    accepted.append(reference.path)
        identities: dict[tuple[int, str], Path] = {}
        unusable = []
        held_files = _held_files(held)
        for held_file in held_files:
            relative = held_file.relative_to(held).as_posix()
            identity = _identity(held_file)
            if identity is None:
                unusable.append({"path": relative, "condition": "unreadable"})
                continue
            if identity not in acceptable:
                if any(relative in paths for paths in acceptable.values()):
                    unusable.append({"path": relative, "condition": "differs_from_reference"})
                continue
            identities.setdefault(identity, held_file)

        offers: dict[str, Offer] = {}
        stored: set[str] = set()
        for target in targets:
            for reference in target.references:
                held_file = identities.get(reference.path_identity)
                if held_file is None:
                    continue
                try:
                    _extract(held_file, reference, target.digest, media, stored)
                except invalid:
                    unusable.append({"path": held_file.relative_to(held).as_posix(),
                                     "condition": "fragment_mismatch"})
                    continue
                offers[target.digest] = Offer(target.digest, reference.part_size,
                                              reference.citation())
                break
        normalized = sorted(offers.values(), key=lambda offer: offer.digest)
        available = {offer.digest for offer in normalized}
        unavailable = tuple(sorted(target.digest for target in targets
                                   if target.digest not in available))
        chosen = token if token is not None else handoff_token(
            request, [offer.as_dict() for offer in normalized])
        reference_id(chosen, "handoff token")
        handoff = Handoff(destination, request, chosen, len(targets), tuple(normalized),
                          unavailable, tuple(sorted(unusable, key=lambda item: item["path"])))
        encoded = json.dumps(handoff.descriptor(), ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")
        if len(encoded) >= MAX_DESCRIPTOR:
            raise invalid("Generated handoff descriptor exceeds its byte limit")
        with (scratch / DESCRIPTOR).open("xb") as target:
            target.write(encoded)
            target.write(b"\n")
            target.flush()
            os.fsync(target.fileno())
        sync_directory(scratch)
        if os.path.lexists(destination):
            raise invalid("Handoff destination already exists", path=str(destination))
        scratch.rename(destination)
        sync_directory(destination.parent)
        return handoff
    finally:
        if scratch.is_dir():
            shutil.rmtree(scratch)


def open_handoff(root: Path) -> Handoff:
    descriptor = root / DESCRIPTOR
    try:
        if descriptor.is_symlink():
            raise invalid("Handoff descriptor must be a regular file")
        with descriptor.open("rb") as source:
            raw = source.read(MAX_DESCRIPTOR + 1)
    except OSError as error:
        raise invalid("Cannot read the repair handoff", detail=str(error)) from error
    if len(raw) > MAX_DESCRIPTOR:
        raise invalid("Repair handoff descriptor exceeds the byte limit")
    try:
        value = read_json(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise invalid("Repair handoff is not unambiguous JSON") from None
    if not isinstance(value, dict) or value.get("format") != FORMAT:
        raise invalid("Repair handoff has an unknown format")
    required = {"format", "request", "token", "targets", "offers", "unavailable", "unusable"}
    if set(value) != required:
        raise invalid("Unexpected fields for repair handoff", required=sorted(required))
    request = value["request"]
    if not isinstance(request, str) or not REQUEST_ID.fullmatch(request):
        raise invalid("Repair handoff has an invalid request identity")
    token = reference_id(value["token"], "handoff token")
    targets = integer(value["targets"], 1, MAX_TARGETS, "handoff target count")
    unavailable = value["unavailable"]
    if not isinstance(unavailable, list) or len(unavailable) > targets:
        raise invalid("Repair handoff has an invalid unavailable list")
    for digest in unavailable:
        sha256(digest)
    raw_offers = value["offers"]
    if not isinstance(raw_offers, list) or len(raw_offers) > targets:
        raise invalid("Repair handoff has an invalid offer list")
    offers = []
    seen = set()
    for offer in raw_offers:
        if not isinstance(offer, dict) or set(offer) != {"digest", "size", "citation"}:
            raise invalid("Unexpected fields for repair offer", required=["digest", "size", "citation"])
        digest = sha256(offer["digest"])
        size = integer(offer["size"], 1, MAX_PART, "offer size")
        citation = offer["citation"]
        if not isinstance(citation, dict) or set(citation) != CITATION_FIELDS:
            raise invalid("Unexpected fields for repair citation", required=sorted(CITATION_FIELDS))
        collection_id(citation["collection"])
        integer(citation["revision"], 1, 2**63 - 1, "citation revision")
        sha256(citation["manifest_sha256"])
        archive_path(citation["path"])
        integer(citation["part_index"], 0, 8191, "citation part index")
        if digest in seen:
            raise invalid("Repair handoff repeats an offer", digest=digest)
        seen.add(digest)
        offers.append(Offer(digest, size, dict(citation)))
    if not set(unavailable).isdisjoint(seen):
        raise invalid("Repair handoff lists an offered object as unavailable")
    unusable = value["unusable"]
    if not isinstance(unusable, list) or len(unusable) > 1000:
        raise invalid("Repair handoff has an invalid unusable list")
    parsed_unusable = []
    for item in unusable:
        if not isinstance(item, dict) or set(item) != {"path", "condition"}:
            raise invalid("Unexpected fields for unusable held file")
        if not isinstance(item["path"], str) or not isinstance(item["condition"], str):
            raise invalid("Unusable held file must describe a path and a condition")
        parsed_unusable.append({"path": item["path"], "condition": item["condition"]})
    handoff = Handoff(root.resolve(), request, token, targets, tuple(offers),
                      tuple(unavailable), tuple(parsed_unusable))
    media = handoff.media()
    for offer in handoff.offers:
        try:
            media.verify(offer.digest, offer.size)
        except Exception:
            raise invalid("Repair handoff material is missing or unreadable", digest=offer.digest) from None
    return handoff
