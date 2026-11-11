from exposureguard.checks._net import url_host


def test_url_host_brackets_ipv6_literals():
    assert url_host("2001:db8::1") == "[2001:db8::1]"


def test_url_host_leaves_dns_and_ipv4_unchanged():
    assert url_host("device.lab.example") == "device.lab.example"
    assert url_host("192.0.2.10") == "192.0.2.10"
