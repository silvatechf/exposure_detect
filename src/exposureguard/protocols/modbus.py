"""Modbus/TCP: ONE read-only request (Read Device Identification, FC 0x2B / MEI 0x0E).

There are deliberately no builders for write function codes in this module.
"""

from __future__ import annotations

READ_DEVICE_ID_FC = 0x2B
_ALLOWED_FUNCTIONS = {READ_DEVICE_ID_FC}


def build_read_device_id(transaction_id: int = 1, unit_id: int = 1) -> bytes:
    pdu = bytes([READ_DEVICE_ID_FC, 0x0E, 0x01, 0x00])  # MEI type 0x0E, basic stream, object 0
    assert pdu[0] in _ALLOWED_FUNCTIONS
    mbap = transaction_id.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + bytes([unit_id])
    return mbap + pdu


def parse_response(data: bytes, transaction_id: int = 1) -> str | None:
    """Return "device_id" for a normal reply, "exception" for a Modbus exception, None if not Modbus."""
    if len(data) < 8 or data[2:4] != b"\x00\x00":
        return None
    if int.from_bytes(data[0:2], "big") != transaction_id:
        return None
    if int.from_bytes(data[4:6], "big") != len(data) - 6:
        return None
    function = data[7]
    if function == READ_DEVICE_ID_FC:
        return "device_id"
    if function == READ_DEVICE_ID_FC | 0x80:
        return "exception"
    return None
