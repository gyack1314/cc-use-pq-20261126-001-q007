"""把外馆制备的修复交割材料送给库房，并取回可重复查看的结算回执。"""

from dataclasses import dataclass
from typing import Protocol

from strata.field.salvage import Handoff
from strata.runtime.errors import unavailable
from strata.runtime.media import BLOCK_SIZE
from strata.transfer.manifest import sha256


class Endpoint(Protocol):
    def request(self, method: str, path: str, **kwargs) -> dict:
        ...


@dataclass(frozen=True)
class Settlement:
    request: str
    token: str
    repaired: tuple[str, ...]
    unresolved: tuple[str, ...]
    transmitted: int
    receipt: dict

    def as_dict(self) -> dict:
        return {"request": self.request, "token": self.token, "repaired": list(self.repaired),
                "unresolved": list(self.unresolved), "transmitted": self.transmitted,
                "settlement": self.receipt}


def send(handoff: Handoff, endpoint: Endpoint) -> Settlement:
    """按交割描述送出材料；重复调用会回到同一批已结算的情况。"""
    media = handoff.media()
    transmitted = 0
    for offer in handoff.offers:
        media.verify(offer.digest, offer.size)
        with media.path(offer.digest).open("rb") as stream:
            reply = endpoint.request(
                "PUT", f"/operations/repairs/{handoff.request}/materials/{offer.digest}",
                content=iter(lambda: stream.read(BLOCK_SIZE), b""),
                headers={"Content-Length": str(offer.size),
                         "Content-Type": "application/octet-stream"},
            )
        if (reply.get("request"), reply.get("digest"), reply.get("size")) != (
            handoff.request, offer.digest, offer.size,
        ):
            raise unavailable("Receipt does not identify the transmitted material",
                              digest=offer.digest)
        transmitted += 1
    receipt = endpoint.request(
        "POST", f"/operations/repairs/{handoff.request}/settlements",
        json={"token": handoff.token, "materials": handoff.materials()},
    )
    return _result(handoff, receipt, transmitted)


def _result(handoff: Handoff, receipt: dict, transmitted: int) -> Settlement:
    if (receipt.get("format") != "strata-repair-settlement-v1"
            or receipt.get("request") != handoff.request
            or receipt.get("token") != handoff.token):
        raise unavailable("Settlement receipt does not match the handoff")
    repaired, unresolved = receipt.get("repaired"), receipt.get("unresolved")
    if not isinstance(repaired, list) or not isinstance(unresolved, list):
        raise unavailable("Settlement receipt has an invalid outcome list")
    for digest in repaired:
        sha256(digest)
    unresolved_digests = []
    for item in unresolved:
        if not isinstance(item, dict) or not isinstance(item.get("digest"), str):
            raise unavailable("Settlement receipt has an invalid unresolved entry")
        unresolved_digests.append(sha256(item["digest"]))
    return Settlement(handoff.request, handoff.token, tuple(repaired),
                      tuple(sorted(unresolved_digests)), transmitted, receipt)
