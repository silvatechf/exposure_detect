import pytest

from exposureguard.protocols import snmp


def test_request_roundtrip():
    version, community, tag = snmp.parse_message(snmp.build_get_request(b"public"))
    assert (version, community, tag) == (1, b"public", snmp.GET_REQUEST)


def test_response_roundtrip():
    _, community, tag = snmp.parse_message(snmp.build_get_response(b"public"))
    assert community == b"public" and tag == snmp.GET_RESPONSE


@pytest.mark.parametrize("junk", [b"", b"\x30", b"\x30\x05\x02", b"hello world"])
def test_malformed_input_raises_valueerror(junk):
    with pytest.raises(ValueError):
        snmp.parse_message(junk)
