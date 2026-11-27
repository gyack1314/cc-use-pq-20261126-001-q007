"""向外馆发出可核对的修复请求，并在交割材料与可信清单相符时恢复共享字节。"""

import hashlib
import json
import os
from pathlib import Path
from sqlite3 import Connection
from typing import BinaryIO
from uuid import uuid4

from strata.preservation.catalog import revision_row
from strata.preservation.integrity import active, resolve
from strata.runtime.database import Database
from strata.runtime.errors import VaultError, conflict, invalid, missing
from strata.runtime.events import append
from strata.runtime.media import BLOCK_SIZE, Media, sync_directory
from strata.transfer.manifest import (
    MAX_PART, archive_path, canonical, collection_id, digest_bytes, integer,
    parse_stored, reference_id, sha256,
)

REQUEST_FORMAT = "strata-repair-request-v1"
SETTLEMENT_FORMAT = "strata-repair-settlement-v1"
MAX_TARGETS = 100
MAX_REFERENCES = 64
CITATION_FIELDS = {"collection", "revision", "manifest_sha256", "path", "part_index"}
OFFER_FIELDS = {"digest", "size", "citation"}


def _measure(source: BinaryIO, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        block = source.read(min(BLOCK_SIZE, remaining))
        if not block:
            raise EOFError
        digest.update(block)
        remaining -= len(block)
    if source.read(1):
        raise OverflowError
    return digest.hexdigest()


def request_row(connection: Connection, request: str):
    row = connection.execute("SELECT * FROM repair_requests WHERE id=?", (request,)).fetchone()
    if row is None:
        raise missing("repair request", request)
    return row


class HandoffStore:
    """保存外馆送来的候选字节；在出处和当前损坏记录都核对通过前不覆盖库内对象。"""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, request: str, digest: str) -> Path:
        return self.root / request / digest

    def install(self, request: str, digest: str, size: int, source: BinaryIO) -> bool:
        path = self.path(request, digest)
        existed = path.is_file()
        temp = path.with_name(f".pending-{uuid4().hex}")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with temp.open("xb") as target:
                source.seek(0)
                computed = hashlib.sha256()
                remaining = size
                while remaining:
                    block = source.read(min(BLOCK_SIZE, remaining))
                    if not block:
                        raise invalid("Handoff material ended before its expected length",
                                      expected=size)
                    computed.update(block)
                    target.write(block)
                    remaining -= len(block)
                if source.read(1):
                    raise invalid("Handoff material exceeds its expected length", expected=size)
                if computed.hexdigest() != digest:
                    raise invalid("Handoff material does not match the requested object", digest=digest)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temp, path)
            sync_directory(path.parent)
            return existed
        except OSError as error:
            raise invalid("Could not store handoff material", digest=digest) from error
        finally:
            temp.unlink(missing_ok=True)

    def condition(self, request: str, digest: str, size: int) -> str:
        try:
            with self.path(request, digest).open("rb") as source:
                return "verified" if _measure(source, size) == digest else "digest_mismatch"
        except FileNotFoundError:
            return "missing"
        except EOFError:
            return "length_mismatch"
        except OSError:
            return "unreadable"

    def open_material(self, request: str, digest: str) -> BinaryIO:
        return self.path(request, digest).open("rb")


class Repairs:
    def __init__(self, db: Database, media: Media, handoff: Path):
        self.db = db
        self.media = media
        self.handoff = HandoffStore(handoff)

    # -- 外送请求 ---------------------------------------------------------

    def open(self, token: str, incidents: list[int]) -> dict:
        reference_id(token, "repair token")
        if not isinstance(incidents, list) or not 1 <= len(incidents) <= MAX_TARGETS:
            raise invalid("A repair request must name 1..%d incidents" % MAX_TARGETS)
        for incident in incidents:
            integer(incident, 1, 2**63 - 1, "incident")
        if len(set(incidents)) != len(incidents):
            raise invalid("A repair request cannot name the same incident twice")
        fingerprint = digest_bytes(canonical({"token": token,
                                              "incidents": sorted(incidents)}).encode("utf-8"))
        with self.db.transaction() as connection:
            now = self.db.now()
            previous = connection.execute(
                "SELECT * FROM repair_requests WHERE token=?", (token,),
            ).fetchone()
            if previous is not None:
                if previous["fingerprint"] != fingerprint:
                    raise conflict("Repair token was used for another request", token=token)
                return self._summary(connection, previous)
            targets = self._resolve_targets(connection, incidents)
            identifier = uuid4().hex
            body = canonical({"token": token, "incidents": sorted(incidents), "targets": targets})
            connection.execute(
                "INSERT INTO repair_requests(id,token,fingerprint,created_at,body) VALUES(?,?,?,?,?)",
                (identifier, token, fingerprint, now, body),
            )
            connection.executemany(
                """INSERT INTO repair_targets(request,digest,size,incident,reason)
                   VALUES(?,?,?,?,?)""",
                ((identifier, target["digest"], target["size"], target["incident"], target["reason"])
                 for target in targets),
            )
            append(connection, None, "repair_requested", identifier, now,
                   token=token, fingerprint=fingerprint, targets=len(targets))
            return self._summary(connection, request_row(connection, identifier))

    def _resolve_targets(self, connection: Connection, incidents: list[int]) -> list[dict]:
        targets = []
        for incident_id in sorted(incidents):
            incident = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if incident is None:
                raise missing("incident", str(incident_id))
            if incident["resolved_at"] is not None:
                raise conflict("Incident is no longer open", incident=incident_id)
            obj = connection.execute("SELECT * FROM objects WHERE digest=?", (incident["digest"],)).fetchone()
            if obj is None:
                raise conflict("Incident has no archive object to repair", incident=incident_id,
                               digest=incident["digest"])
            if obj["sweep_state"] != "live":
                raise conflict("Archive object is being reclaimed", incident=incident_id,
                               digest=incident["digest"])
            references = self._references(connection, incident["digest"], obj["size"])
            if not references:
                raise conflict("No trusted manifest places this object in a file",
                               incident=incident_id, digest=incident["digest"])
            targets.append({"digest": incident["digest"], "size": obj["size"],
                            "incident": incident_id, "reason": incident["reason"],
                            "references": references})
        return targets

    def _references(self, connection: Connection, digest: str, size: int) -> list[dict]:
        """列出可信清单里该字节的文件与分片位置；退役版本只用于核对出处。"""
        revisions = connection.execute(
            """SELECT r.collection,r.number,r.retired_at,r.manifest,r.manifest_hash
               FROM revisions r JOIN revision_parts p
               ON p.collection=r.collection AND p.number=r.number
               WHERE p.digest=? ORDER BY (r.retired_at IS NOT NULL),r.collection,r.number""",
            (digest,),
        ).fetchall()
        found = []
        for revision in revisions:
            try:
                manifest = parse_stored(revision["manifest"], revision["manifest_hash"])
            except (VaultError, RuntimeError, ValueError, RecursionError):
                continue
            for entry in manifest.files:
                offset = 0
                for index, part in enumerate(entry.parts):
                    if part.digest == digest:
                        if part.size != size:
                            raise conflict("Manifest fragment length differs from the stored object",
                                           digest=digest)
                        if len(found) < MAX_REFERENCES:
                            found.append({
                                "collection": revision["collection"], "revision": revision["number"],
                                "manifest_sha256": revision["manifest_hash"],
                                "retired": revision["retired_at"] is not None,
                                "path": entry.path, "file_sha256": entry.digest,
                                "file_size": entry.size, "part_index": index,
                                "part_offset": offset, "part_size": part.size,
                            })
                    offset += part.size
        return found

    def get(self, request: str) -> dict:
        with self.db.transaction(write=False) as connection:
            return self._summary(connection, request_row(connection, request))

    def _summary(self, connection: Connection, row) -> dict:
        body = json.loads(row["body"])
        targets = []
        for target in connection.execute(
            "SELECT * FROM repair_targets WHERE request=? ORDER BY digest", (row["id"],),
        ):
            references = next((item["references"] for item in body["targets"]
                               if item["digest"] == target["digest"]), [])
            targets.append({"digest": target["digest"], "size": target["size"],
                            "incident": target["incident"], "reason": target["reason"],
                            "references": references})
        materials = [dict(item) for item in connection.execute(
            "SELECT digest,size,received_at FROM repair_materials WHERE request=? ORDER BY digest",
            (row["id"],))]
        settlements = []
        for settlement in connection.execute(
            "SELECT token,settled_at,receipt FROM repair_settlements "
            "WHERE request=? ORDER BY settled_at,token", (row["id"],)):
            receipt = json.loads(settlement["receipt"])
            settlements.append({"token": settlement["token"], "settled_at": settlement["settled_at"],
                                "repaired": receipt["repaired"],
                                "unresolved": [item["digest"] for item in receipt["unresolved"]]})
        return {"format": REQUEST_FORMAT, "id": row["id"], "token": row["token"],
                "fingerprint": row["fingerprint"], "created_at": row["created_at"],
                "targets": targets, "materials": materials, "settlements": settlements}

    # -- 交割材料 ---------------------------------------------------------

    def material_size(self, request: str, digest: str) -> int:
        sha256(digest)
        with self.db.transaction(write=False) as connection:
            request_row(connection, request)
            return self._target_size(connection, request, digest)

    @staticmethod
    def _target_size(connection: Connection, request: str, digest: str) -> int:
        row = connection.execute(
            "SELECT size FROM repair_targets WHERE request=? AND digest=?", (request, digest),
        ).fetchone()
        if row is None:
            raise missing("repair target", digest)
        return row["size"]

    def receive_material(self, request: str, digest: str, source: BinaryIO) -> dict:
        """先完整校验再落盘；重送的同一字节保留原收据，不覆盖库内对象。"""
        size = self.material_size(request, digest)
        self.media.validate_upload(digest, size, source)
        duplicate = self.handoff.install(request, digest, size, source)
        with self.db.transaction() as connection:
            now = self.db.now()
            request_row(connection, request)
            self._target_size(connection, request, digest)
            cursor = connection.execute(
                "INSERT OR IGNORE INTO repair_materials(request,digest,size,received_at) VALUES(?,?,?,?)",
                (request, digest, size, now),
            )
            if cursor.rowcount:
                append(connection, None, "repair_material_received", request, now,
                       digest=digest, size=size)
            return {"request": request, "digest": digest, "size": size,
                    "duplicate": duplicate or not cursor.rowcount}

    # -- 交割结算 ---------------------------------------------------------

    def settle(self, request: str, token: str, materials: list[dict]) -> dict:
        reference_id(token, "settlement token")
        offers = _offers(materials)
        fingerprint = _fingerprint(token, offers)
        with self.db.transaction() as connection:
            row = request_row(connection, request)
            previous = connection.execute(
                "SELECT * FROM repair_settlements WHERE request=? AND token=?", (request, token),
            ).fetchone()
            if previous is not None:
                if previous["fingerprint"] != fingerprint:
                    raise conflict("Settlement token was used for another handoff", token=token)
                return json.loads(previous["receipt"])
            now = self.db.now()
            targets = connection.execute(
                "SELECT * FROM repair_targets WHERE request=? ORDER BY digest", (request,),
            ).fetchall()
            known = {target["digest"]: target for target in targets}
            offered = {offer["digest"]: offer for offer in offers}
            for digest in sorted(offered.keys() - known.keys()):
                raise invalid("Handoff offers material the request did not target", digest=digest)
            outcomes = [self._settle_target(connection, row, target,
                                            offered.get(target["digest"]), now)
                        for target in targets]
            receipt = _receipt(row, token, fingerprint, now, outcomes)
            connection.execute(
                """INSERT INTO repair_settlements(request,token,fingerprint,settled_at,receipt)
                   VALUES(?,?,?,?,?)""",
                (request, token, fingerprint, now, canonical(receipt)),
            )
            append(connection, None, "repair_settled", request, now, token=token,
                   fingerprint=fingerprint, repaired=len(receipt["repaired"]),
                   unresolved=len(receipt["unresolved"]))
            return receipt

    def _settle_target(self, connection: Connection, request, target, offer, now: int) -> dict:
        digest, size, incident = target["digest"], target["size"], target["incident"]
        base = {"digest": digest, "incident": incident}
        if offer is None:
            return {**base, "outcome": "not_offered", "reason": "material_not_offered"}
        if offer["size"] != size:
            return {**base, "outcome": "rejected", "reason": "material_length_differs"}
        obj = connection.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone()
        if obj is None:
            return {**base, "outcome": "unresolved", "reason": "object_reclaimed"}
        if obj["sweep_state"] != "live":
            return {**base, "outcome": "unresolved", "reason": "object_being_reclaimed"}
        current = active(connection, digest)
        if current is None:
            return {**base, "outcome": "already_resolved", "reason": "no_open_incident"}
        if current["id"] != incident:
            return {**base, "outcome": "unresolved", "reason": "incident_superseded",
                    "current_incident": current["id"]}
        citation = self._verify_citation(connection, offer["citation"], digest, size)
        if citation is None:
            return {**base, "outcome": "rejected", "reason": "citation_does_not_match"}
        condition = self.handoff.condition(request["id"], digest, size)
        if condition == "missing":
            return {**base, "outcome": "unresolved", "reason": "material_missing"}
        if condition != "verified":
            return {**base, "outcome": "rejected", "reason": "material_does_not_match_object",
                    "condition": condition}
        with self.handoff.open_material(request["id"], digest) as source:
            self.media.install(digest, size, source)
        connection.execute("UPDATE objects SET verified_at=? WHERE digest=?", (now, digest))
        resolve(connection, digest, now, "handoff")
        append(connection, citation["collection"], "object_repaired", digest, now,
               request=request["id"], incident=incident, source=citation)
        return {**base, "outcome": "repaired", "citation": citation}

    @staticmethod
    def _verify_citation(connection: Connection, citation: dict, digest: str,
                         size: int) -> dict | None:
        """只用可信清单核对文件与分片位置；退役版本可作来源，但不重发其字节。"""
        try:
            row = revision_row(connection, citation["collection"], citation["revision"])
        except VaultError:
            return None
        if row["manifest_hash"] != citation["manifest_sha256"]:
            return None
        try:
            manifest = parse_stored(row["manifest"], row["manifest_hash"])
            entry = manifest.file(citation["path"])
        except (VaultError, RuntimeError, ValueError, RecursionError):
            return None
        if entry is None:
            return None
        index = citation["part_index"]
        if index >= len(entry.parts):
            return None
        part = entry.parts[index]
        if part.digest != digest or part.size != size:
            return None
        return {"collection": citation["collection"], "revision": citation["revision"],
                "manifest_sha256": row["manifest_hash"], "path": entry.path,
                "file_sha256": entry.digest, "part_index": index,
                "retired": row["retired_at"] is not None}

    def settlement(self, request: str, token: str) -> dict:
        reference_id(token, "settlement token")
        with self.db.transaction(write=False) as connection:
            request_row(connection, request)
            row = connection.execute(
                "SELECT receipt FROM repair_settlements WHERE request=? AND token=?",
                (request, token),
            ).fetchone()
            if row is None:
                raise missing("repair settlement", token)
            return json.loads(row["receipt"])


def _offers(materials: list[dict]) -> list[dict]:
    if not isinstance(materials, list) or len(materials) > MAX_TARGETS:
        raise invalid("A handoff must offer at most %d materials" % MAX_TARGETS)
    offers = []
    seen = set()
    for offer in materials:
        if not isinstance(offer, dict) or set(offer) != OFFER_FIELDS:
            raise invalid("Unexpected fields for repair material", required=sorted(OFFER_FIELDS))
        digest = sha256(offer["digest"])
        size = integer(offer["size"], 1, MAX_PART, "material size")
        citation = offer["citation"]
        if not isinstance(citation, dict) or set(citation) != CITATION_FIELDS:
            raise invalid("Unexpected fields for repair citation",
                          required=sorted(CITATION_FIELDS))
        citation = {
            "collection": collection_id(citation["collection"]),
            "revision": integer(citation["revision"], 1, 2**63 - 1, "citation revision"),
            "manifest_sha256": sha256(citation["manifest_sha256"]),
            "path": archive_path(citation["path"]),
            "part_index": integer(citation["part_index"], 0, 8191, "citation part index"),
        }
        if digest in seen:
            raise invalid("A handoff cannot offer the same object twice", digest=digest)
        seen.add(digest)
        offers.append({"digest": digest, "size": size, "citation": citation})
    return sorted(offers, key=lambda item: item["digest"])


def _fingerprint(token: str, offers: list[dict]) -> str:
    return digest_bytes(canonical({"token": token, "materials": offers}).encode("utf-8"))


def _receipt(row, token: str, fingerprint: str, now: int, outcomes: list[dict]) -> dict:
    repaired = [item["digest"] for item in outcomes if item["outcome"] == "repaired"]
    unresolved = [item for item in outcomes
                  if item["outcome"] not in ("repaired", "already_resolved")]
    return {"format": SETTLEMENT_FORMAT, "request": row["id"], "token": token,
            "fingerprint": fingerprint, "settled_at": now, "outcomes": outcomes,
            "repaired": repaired, "unresolved": unresolved}
