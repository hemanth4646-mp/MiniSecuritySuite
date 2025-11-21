from password_checker import check_password_strength


def test_weak():
    assert check_password_strength("abc") == "Weak Password ❌"


def test_strong():
    assert check_password_strength("Abc123!@#") == "Strong Password ✅"
