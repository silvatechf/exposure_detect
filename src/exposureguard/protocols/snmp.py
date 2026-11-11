"""Minimal BER/SNMPv2c helpers: build a GetRequest for sysDescr and parse replies."""

from __future__ import annotations

SYS_DESCR_OID = bytes.fromhex("2b06010201010100")  # 1.3.6.1.2.1.1.1.0
GET_REQUEST, GET_RESPONSE = 0xA0, 0xA2


def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 128:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def read_tlv(data: bytes, off: int = 0) -> tuple[int, int, int]:
    try:
        tag, first = data[off], data[off + 1]
        if first < 128:
            start, end = off + 2, off + 2 + first
        else:
            k = first & 0x7F
            n = int.from_bytes(data[off + 2 : off + 2 + k], "big")
            start, end = off + 2 + k, off + 2 + k + n
    except IndexError as exc:
        raise ValueError("truncated BER data") from exc
    if end > len(data):
        raise ValueError("BER length exceeds data")
    return tag, start, end


def build_get_request(community: bytes, request_id: int = 1) -> bytes:
    varbind = tlv(0x30, tlv(0x06, SYS_DESCR_OID) + tlv(0x05, b""))
    pdu = tlv(
        GET_REQUEST,
        tlv(2, bytes([request_id])) + tlv(2, b"\x00") + tlv(2, b"\x00") + tlv(0x30, varbind),
    )
    return tlv(0x30, tlv(2, b"\x01") + tlv(4, community) + pdu)


def build_get_response(community: bytes, request_id: int = 1, descr: bytes = b"FakeDevice") -> bytes:
    varbind = tlv(0x30, tlv(0x06, SYS_DESCR_OID) + tlv(4, descr))
    pdu = tlv(
        GET_RESPONSE,
        tlv(2, bytes([request_id])) + tlv(2, b"\x00") + tlv(2, b"\x00") + tlv(0x30, varbind),
    )
    return tlv(0x30, tlv(2, b"\x01") + tlv(4, community) + pdu)


def parse_message(data: bytes) -> tuple[int, bytes, int]:
    """Return (version, community, pdu_tag). Raises ValueError on malformed input."""
    tag, start, _ = read_tlv(data)
    if tag != 0x30:
        raise ValueError("not an SNMP message")
    _, vs, ve = read_tlv(data, start)
    _, cs, ce = read_tlv(data, ve)
    pdu_tag, _, _ = read_tlv(data, ce)
    return int.from_bytes(data[vs:ve], "big"), data[cs:ce], pdu_tag
