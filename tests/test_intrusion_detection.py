from intrusion_detection import extract_raddr


class RAddrObj:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


def test_extract_tuple():
    assert extract_raddr(("1.2.3.4", 80)) == ("1.2.3.4", 80)


def test_extract_obj():
    o = RAddrObj("5.6.7.8", 443)
    assert extract_raddr(o) == ("5.6.7.8", 443)


def test_extract_iterable():
    class Fake:
        def __iter__(self):
            return iter(("9.9.9.9", 22))

    assert extract_raddr(Fake()) == ("9.9.9.9", 22)
