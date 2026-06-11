from pyscout.models import normalize_domain


def test_normalize_domain():
    assert normalize_domain("https://www.example.com/path") == "example.com"
    assert normalize_domain("EXAMPLE.COM") == "example.com"
