from io import BytesIO
import json
from pathlib import Path

from strata.field.handoff import send
from strata.field.salvage import handoff_token, open_handoff, prepare_salvage
from strata.runtime.errors import VaultError
from support import Scenario, sha


class InProcessEndpoint:
    """把外馆侧命令接到测试中的库房接口，不经过网络。"""

    def __init__(self, http):
        self.http = http
        self.calls = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path))
        reply = self.http.request(method, path, **kwargs)
        value = reply.json()
        if reply.is_error:
            error = value["error"]
            raise VaultError(error["code"], error["message"], reply.status_code, **error["details"])
        return value


class RepairHandoff(Scenario):
    def write_request(self, request: dict, name: str = "request.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(request, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        return path

    def outbound(self, incidents: dict, token: str = "outbound-01") -> dict:
        return self.http.post("/operations/repairs",
                              json={"token": token, "incidents": [incidents["id"]]}).json()

    def held_files(self, files: dict[str, bytes]) -> Path:
        held = self.root / "held"
        held.mkdir(exist_ok=True)
        for path, data in files.items():
            target = held.joinpath(*path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return held

    def test_shared_byte_is_repairable_from_a_retired_reference(self):
        self.edition("v1", {"plate": [b"shared", b"tail"]})
        self.edition("v2", {"plate": [b"shared"], "extra": [b"keep"]}, parent=1)
        self.clock.advance(60)
        self.vault.custody.retire("ridge", 1)
        self.vault.media.path(sha(b"shared")).unlink()
        self.vault.integrity.scan(limit=20)
        incident = next(item for item in self.vault.integrity.incidents(
            after=0, limit=20, open_only=True)["items"] if item["digest"] == sha(b"shared"))
        self.assertEqual({item["number"] for item in incident["revisions"]}, {1, 2})

        request = self.outbound(incident)
        reference_set = request["targets"][0]["references"]
        self.assertEqual([item["retired"] for item in reference_set], [False, True])
        self.assertEqual([(item["revision"], item["path"], item["part_index"]) for item in reference_set],
                         [(2, "plate", 0), (1, "plate", 0)])
        held = self.held_files({"plate": b"sharedtail"})
        handoff = prepare_salvage(held, self.root / "handoff",
                                  request_path=self.write_request(request))
        self.assertEqual([offer.digest for offer in handoff.offers], [sha(b"shared")])
        self.assertEqual(handoff.unavailable, ())
        station = InProcessEndpoint(self.http)
        settled = send(open_handoff(self.root / "handoff"), station)
        self.assertEqual(settled.repaired, (sha(b"shared"),))
        self.assertEqual(settled.unresolved, ())
        self.assertEqual(self.vault.catalog.revision("ridge", 1)["state"], "retired")
        self.assertEqual(self.vault.catalog.revision("ridge", 2)["state"], "available")
        self.assertEqual(self.vault.inspection.coverage("ridge", 1)["files"][0]["restorable"], False)
        self.assertTrue(self.vault.inspection.coverage("ridge", 2)["files"][0]["restorable"])
        self.assertEqual(self.http.get("/collections/ridge/revisions/2/package").status_code, 200)
        self.assertEqual(self.http.get("/collections/ridge/revisions/1/package").status_code, 410)

    def test_stale_response_does_not_close_a_later_incident(self):
        self.edition("v1", {"plate": [b"shared"]})
        self.vault.media.path(sha(b"shared")).write_bytes(b"worn")
        self.vault.integrity.scan(limit=20)
        # 外馆仍按第一次请求制备材料；提交前库内已经用单片修复修好了该对象。
        request = self.outbound(self.vault.integrity.incidents(
            after=0, limit=20, open_only=True)["items"][0])
        first = self.vault.integrity.incidents(after=0, limit=20, open_only=True)["items"][0]
        self.vault.integrity.repair(sha(b"shared"), first["id"], BytesIO(b"shared"))
        held = self.held_files({"plate": b"shared"})
        handoff = prepare_salvage(held, self.root / "handoff",
                                  request_path=self.write_request(request))
        station = InProcessEndpoint(self.http)
        settled = send(open_handoff(self.root / "handoff"), station)
        self.assertEqual(settled.repaired, ())
        self.assertEqual(settled.receipt["outcomes"][0]["outcome"], "already_resolved")

    def test_repeated_handoff_reads_back_the_same_settlement_after_restart(self):
        self.edition("v1", {"a": [b"one"], "b": [b"two"]})
        self.vault.media.path(sha(b"one")).unlink()
        self.vault.media.path(sha(b"two")).unlink()
        self.vault.integrity.scan(limit=20)
        incidents = self.vault.integrity.incidents(after=0, limit=20, open_only=True)["items"]
        request = self.outbound_many([item["id"] for item in incidents], token="batch")
        held = self.held_files({"a": b"one", "b": b"two"})
        handoff = prepare_salvage(held, self.root / "handoff", request_path=self.write_request(request))
        station = InProcessEndpoint(self.http)
        first = send(open_handoff(self.root / "handoff"), station)
        self.assertEqual(len(first.repaired), 2)
        self.restart()
        replay = send(open_handoff(self.root / "handoff"), InProcessEndpoint(self.http))
        self.assertEqual(replay.repaired, first.repaired)
        self.assertEqual(replay.receipt["settled_at"], first.receipt["settled_at"])
        self.assertEqual(self.http.get(f"/operations/repairs/{request['id']}").json()["settlements"][0]["token"],
                         first.token)

    def outbound_many(self, incidents: list[int], token: str) -> dict:
        return self.http.post("/operations/repairs",
                              json={"token": token, "incidents": incidents}).json()

    def test_partial_handoff_settles_confirmed_fragments_and_keeps_other_reasons(self):
        self.edition("v1", {"a": [b"one"], "broken": [b"two"]})
        self.vault.media.path(sha(b"one")).unlink()
        self.vault.media.path(sha(b"two")).unlink()
        self.vault.integrity.scan(limit=20)
        incidents = self.vault.integrity.incidents(after=0, limit=20, open_only=True)["items"]
        request = self.outbound_many([item["id"] for item in incidents], token="partial")
        held = self.held_files({"a": b"one", "broken": b"worn"})
        handoff = prepare_salvage(held, self.root / "handoff", request_path=self.write_request(request))
        self.assertEqual([offer.digest for offer in handoff.offers], [sha(b"one")])
        self.assertEqual(handoff.unavailable, (sha(b"two"),))
        self.assertEqual(handoff.unusable[0]["condition"], "differs_from_reference")
        station = InProcessEndpoint(self.http)
        settled = send(open_handoff(self.root / "handoff"), station)
        self.assertEqual(settled.repaired, (sha(b"one"),))
        self.assertEqual(settled.unresolved, (sha(b"two"),))
        self.assertEqual(self.vault.catalog.revision("ridge", 1)["state"], "degraded")
        coverage = self.vault.inspection.coverage("ridge", 1)
        self.assertEqual({item["path"]: item["restorable"] for item in coverage["files"]},
                        {"a": True, "broken": False})

    def test_material_for_another_object_is_rejected(self):
        self.edition("v1", {"plate": [b"shared"]})
        self.vault.media.path(sha(b"shared")).unlink()
        self.vault.integrity.scan(limit=20)
        incident = self.vault.integrity.incidents(after=0, limit=20, open_only=True)["items"][0]
        request = self.outbound(incident)
        received = self.http.put(f"/operations/repairs/{request['id']}/materials/{sha(b'shared')}",
                                 content=b"other",
                                 headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(received.status_code, 422)
        self.assertEqual(self.vault.catalog.revision("ridge", 1)["state"], "degraded")
        body = self.http.post(f"/operations/repairs/{request['id']}/settlements",
                              json={"token": "x", "materials": [{
                                  "digest": sha(b"shared"), "size": 6,
                                  "citation": {"collection": "ridge", "revision": 1,
                                               "manifest_sha256": self.vault.catalog.revision(
                                                   "ridge", 1)["manifest_sha256"],
                                               "path": "plate", "part_index": 0}}]}).json()
        self.assertEqual(body["outcomes"][0]["outcome"], "unresolved")
        self.assertEqual(body["outcomes"][0]["reason"], "material_missing")

    def test_citation_must_match_the_trusted_file_and_fragment_position(self):
        self.edition("v1", {"plate": [b"shared", b"tail"]})
        self.vault.media.path(sha(b"shared")).unlink()
        self.vault.integrity.scan(limit=20)
        incident = self.vault.integrity.incidents(after=0, limit=20, open_only=True)["items"][0]
        request = self.outbound(incident)
        received = self.http.put(f"/operations/repairs/{request['id']}/materials/{sha(b'shared')}",
                                 content=b"shared",
                                 headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(received.status_code, 200)
        reference = request["targets"][0]["references"][0]
        base = {"collection": "ridge", "revision": 1,
                "manifest_sha256": reference["manifest_sha256"], "path": "plate"}
        for part_index in (1, 0):
            citation = {**base, "part_index": part_index}
            body = self.http.post(f"/operations/repairs/{request['id']}/settlements",
                                  json={"token": f"citation-{part_index}", "materials": [{
                                      "digest": sha(b"shared"), "size": 6, "citation": citation}]}).json()
            if part_index == 1:
                self.assertEqual(body["outcomes"][0]["outcome"], "rejected")
                self.assertEqual(body["outcomes"][0]["reason"], "citation_does_not_match")
                self.assertEqual(self.vault.catalog.revision("ridge", 1)["state"], "degraded")
            else:
                self.assertEqual(body["outcomes"][0]["outcome"], "repaired")
                self.assertEqual(self.vault.catalog.revision("ridge", 1)["state"], "available")

    def test_object_without_a_trusted_manifest_reference_cannot_be_requested(self):
        opened = self.open("unpublished", {"f": [b"stranded"]})
        self.upload(opened["id"], b"stranded")
        self.vault.media.path(sha(b"stranded")).write_bytes(b"worn")
        self.vault.integrity.scan(limit=20)
        incident = next(item for item in self.vault.integrity.incidents(
            after=0, limit=20, open_only=True)["items"] if item["digest"] == sha(b"stranded"))
        with self.assertRaisesRegex(VaultError, "trusted manifest"):
            self.vault.repairs.open("unpublished-target", [incident["id"]])
        self.assertEqual(self.vault.deposits.get(opened["id"])["status"], "open")

    def test_full_handoff_settles_conflict_free_fragments_without_voiding_the_batch(self):
        self.edition("v1", {"a": [b"one"], "b": [b"two"]})
        self.vault.media.path(sha(b"one")).unlink()
        self.vault.media.path(sha(b"two")).write_bytes(b"worn")
        self.vault.integrity.scan(limit=20)
        incidents = self.vault.integrity.incidents(after=0, limit=20, open_only=True)["items"]
        request = self.outbound_many([item["id"] for item in incidents], token="mixed")
        held = self.held_files({"a": b"one", "b": b"two"})
        handoff = prepare_salvage(held, self.root / "handoff", request_path=self.write_request(request))
        self.assertEqual(len(handoff.offers), 2)
        settled = send(open_handoff(self.root / "handoff"), InProcessEndpoint(self.http))
        self.assertEqual(sorted(settled.repaired), sorted((sha(b"one"), sha(b"two"))))
        self.assertEqual(settled.unresolved, ())
        self.assertEqual(len(self.vault.integrity.incidents(after=0, limit=9, open_only=True)["items"]), 0)

    def test_new_incident_after_response_keeps_the_fragment_unresolved(self):
        self.edition("v1", {"a": [b"one"], "b": [b"two"]})
        self.vault.media.path(sha(b"one")).unlink()
        self.vault.media.path(sha(b"two")).unlink()
        self.vault.integrity.scan(limit=20)
        incidents = self.vault.integrity.incidents(after=0, limit=20, open_only=True)["items"]
        request = self.outbound_many([item["id"] for item in incidents], token="renewed")
        held = self.held_files({"a": b"one", "b": b"two"})
        handoff = prepare_salvage(held, self.root / "handoff", request_path=self.write_request(request))
        # 材料送达前，单片修复把 "two" 修好，随后介质再次损坏并开出新记录。
        old = next(item for item in incidents if item["digest"] == sha(b"two"))
        self.vault.integrity.repair(sha(b"two"), old["id"], BytesIO(b"two"))
        self.vault.media.path(sha(b"two")).write_bytes(b"worn")
        self.vault.integrity.scan(limit=20)
        renewed = next(item for item in self.vault.integrity.incidents(
            after=0, limit=20, open_only=True)["items"] if item["digest"] == sha(b"two"))
        self.assertNotEqual(renewed["id"], old["id"])
        settled = send(open_handoff(self.root / "handoff"), InProcessEndpoint(self.http))
        self.assertEqual(settled.repaired, (sha(b"one"),))
        self.assertEqual(settled.unresolved, (sha(b"two"),))
        outcome = next(item for item in settled.receipt["outcomes"] if item["digest"] == sha(b"two"))
        self.assertEqual(outcome["outcome"], "unresolved")
        self.assertEqual(outcome["reason"], "incident_superseded")
        self.assertEqual(outcome["current_incident"], renewed["id"])

    def test_request_requires_trusted_reference_and_known_incident(self):
        self.edition("v1", {"plate": [b"shared"]})
        with self.assertRaises(VaultError):
            self.vault.repairs.open("no-incident", [999])
        self.vault.media.path(sha(b"shared")).unlink()
        self.vault.integrity.scan(limit=20)
        incident = self.vault.integrity.incidents(after=0, limit=20, open_only=True)["items"][0]
        first = self.outbound(incident)
        with self.assertRaisesRegex(VaultError, "another request"):
            self.vault.repairs.open("outbound-01", [incident["id"], 999])
        self.assertEqual(self.http.get(f"/operations/repairs/{first['id']}").json()["fingerprint"],
                         first["fingerprint"])
        self.assertEqual(handoff_token(first["id"], []), handoff_token(first["id"], []))
